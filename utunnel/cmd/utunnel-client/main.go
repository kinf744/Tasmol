package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"utunnel/proto"

	"github.com/quic-go/quic-go"
)

// ── Transport QUIC du tunnel utunnel ───────────────────────────────────
//
// Le transport PROUVÉ sur les réseaux mobiles hostiles : le QUIC est
// indistinguable du trafic HTTPS/3 légitime (le DPI le whitelist — le
// zivpn/Hysteria pousse 18 Mo+ sur le même réseau).
//
// L'identité utunnel PRÉSERVÉE : l'auth PSK (SHA256(uuid:secret) servie
// par l'API stivaros), la plage de ports (50000-59999 DNAT-ée), les
// streams TCP/UDP, le port hopping (la re-dial adaptative).
//
// Protocole par-dessus QUIC :
//   - Le premier stream : [2B len][PSK] → l'auth (le serveur vérifie) ;
//   - 1 stream bidirectionnel par CONNECT : [2B len][addr][status 1B]
//     puis le bridge TCP bidirectionnel ;
//   - Les datagrammes QUIC : [2B len][dst][payload] (le relais UDP/DNS).

var (
	serverAddr = flag.String("server", "", "serveur:port ou serveur:plage (50000-59999)")
	pskHex     = flag.String("key", "", "PSK hex (32 octets) — ou fichier via -key-file")
	pskFile    = flag.String("key-file", "", "fichier contenant la PSK")
	socksAddr  = flag.String("socks", "127.0.0.1:10080", "écoute SOCKS5 locale")
	certFile   = flag.String("cert", "", "cert.pem du serveur (insecure si vide)")
	hopMin     = flag.Int("hop-min", 10, "intervalle du re-dial adaptatif (secondes)")
)

var connectStart time.Time

func main() {
	flag.Parse()
	if *serverAddr == "" {
		log.Fatal("--server requis")
	}
	psk, err := loadPSK()
	if err != nil {
		log.Fatal(err)
	}

	// La connexion QUIC (le port initial aléatoire dans la plage — la
	// spec Hysteria). Les hops : le re-dial adaptatif (déjà prouvé).
	var qconn quic.Connection
	deadline := time.Now().Add(60 * time.Second)
	for {
		dctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		qconn, err = proto.DialQUIC(dctx, *serverAddr)
		cancel()
		if err == nil {
			break
		}
		log.Printf("dial %s: %v — nouvelle tentative dans 2s", *serverAddr, err)
		if time.Now().After(deadline) {
			log.Fatal("délai de connexion dépassé")
		}
		time.Sleep(2 * time.Second)
	}
	log.Printf("tunnel établi vers %s (QUIC)", qconn.RemoteAddr())

	// L'AUTH : le premier stream = [2B len][PSK] — le serveur vérifie
	// (le PSK = SHA256(uuid:secret) ou la PSK brute).
	astream, err := proto.AuthStream(qconn, pskString(psk), 15*time.Second)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	// Le canal d'auth reste ouvert (la session vit tant que le stream vit).
	defer astream.Close()
	log.Printf("auth OK (PSK acceptée par le serveur)")
	sessPtr.Store(&quicSess{conn: qconn})

	// Le re-dial adaptatif : si la connexion QUIC meurt (le downlink figé),
	// relancer un dial — le port hopping automatique (proven working).
	go func() {
		<-qconn.Context().Done()
		log.Printf("connexion QUIC fermée — re-dial avec hop destination")
		for {
			dctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			nq, err := proto.DialQUIC(dctx, *serverAddr)
			cancel()
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}
			if _, aerr := proto.AuthStream(nq, pskString(psk), 15*time.Second); aerr != nil {
				nq.CloseWithError(0, "auth failed")
				time.Sleep(2 * time.Second)
				continue
			}
			sessPtr.Store(&quicSess{conn: nq})
			log.Printf("re-dial OK (QUIC) vers %s", nq.RemoteAddr())
			return
		}
	}()

	lsn, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("SOCKS5 en écoute sur %s", lsn.Addr())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		lsn.Close()
		os.Exit(0)
	}()

	for {
		c, err := lsn.Accept()
		if err != nil {
			return
		}
		go handleSOCKSQuic(sessPtr.Load(), c)
	}
}

// quicSess : la session QUIC courante (remplacée au re-dial).
type quicSess struct{ conn quic.Connection }

var sessPtr atomic.Pointer[quicSess]

// pskString : la PSK brute (les octets) → la string pour l'auth
// (le serveur : auth.config = les PSK pré-calculées — le match exact).
func pskString(psk []byte) string {
	// L'API sert SHA256(uuid:secret) ; le profil : la 64-hex → directe.
	// Sinon : SHA256 du secret brut (le serveur : les deux acceptés —
	// auth.config inclut les hashes ET les PSK statiques).
	if len(psk) == 32 {
		return hex.EncodeToString(psk)
	}
	return string(psk)
}

func loadPSK() ([]byte, error) {
	if *pskHex != "" {
		if len(*pskHex) != 64 {
			return nil, errors.New("clé hex doit faire 64 caractères (32 octets)")
		}
		out := make([]byte, 32)
		for i := 0; i < 32; i++ {
			if _, err := fmt.Sscanf((*pskHex)[i*2:i*2+2], "%02x", &out[i]); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	if *pskFile != "" {
		b, err := os.ReadFile(*pskFile)
		if err != nil {
			return nil, err
		}
		return proto.LoadPSKFromString(string(b))
	}
	return nil, errors.New("aucune PSK fournie (-key ou -key-file)")
}

// handleSOCKSQuic : le SOCKS5 → le transport QUIC.
func handleSOCKSQuic(s *quicSess, c net.Conn) {
	defer c.Close()
	buf := make([]byte, 4096)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	nmeth := int(buf[1])
	io.ReadFull(c, buf[:nmeth])
	c.Write([]byte{5, 0})

	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	cmd := buf[1]
	atyp := buf[3]
	var addr string
	switch atyp {
	case 1:
		io.ReadFull(c, buf[:6])
		addr = fmt.Sprintf("%d.%d.%d.%d:%d", buf[0], buf[1], buf[2], buf[3], binary.BigEndian.Uint16(buf[4:]))
	case 3:
		io.ReadFull(c, buf[:1])
		l := int(buf[0])
		io.ReadFull(c, buf[:l+2])
		addr = fmt.Sprintf("%s:%d", string(buf[:l]), binary.BigEndian.Uint16(buf[l:]))
	default:
		return
	}

	switch cmd {
	case 1: // CONNECT → 1 stream QUIC bidirectionnel
		t0 := time.Now()
		st, err := s.conn.OpenStreamSync(context.Background())
		if err != nil {
			log.Printf("CONNECT %s ÉCHEC en %dms : %v", addr, time.Since(t0).Milliseconds(), err)
			c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		// [2B len][addr] — le serveur : dial le target et répond.
		var hdr [2]byte
		hdr[0] = byte(len(addr) >> 8)
		hdr[1] = byte(len(addr))
		if _, err := st.Write(append(hdr[:], []byte(addr)...)); err != nil {
			log.Printf("CONNECT %s ÉCHEC (envoi) : %v", addr, err)
			st.Close()
			c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		var status [1]byte
		if _, err := io.ReadFull(st, status[:]); err != nil {
			log.Printf("CONNECT %s ÉCHEC en %dms : %v", addr, time.Since(t0).Milliseconds(), err)
			st.Close()
			c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		log.Printf("CONNECT %s établi en %dms", addr, time.Since(t0).Milliseconds())
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		// Le bridge bidirectionnel (le TCP target).
		done := make(chan struct{}, 2)
		go func() { io.Copy(st, c); st.Close(); done <- struct{}{} }()
		go func() { io.Copy(c, st); done <- struct{}{} }()
		<-done
		st.Close()
	case 3: // UDP ASSOCIATE → les datagrammes QUIC (le relais DNS/UDP)
		proto.UDPAssociateOverQUIC(s.conn, c)
	}
}
