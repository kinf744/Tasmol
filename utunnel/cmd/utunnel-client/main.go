// utunnel-client : extrémité cliente du tunnel.
//
//   - expose un proxy SOCKS5 local (--socks 127.0.0.1:1080) ;
//   - relaie TCP (CONNECT) et UDP (ASSOCIATE) via le tunnel ;
//   - rotation du port source : une nouvelle socket UDP éphémère par rafale
//     (le serveur suit l'adresse du pair à chaque paquet — port hopping
//     gratuit et cadencé) ;
//   - obfuscation : handshake paddé, aucun motif fixe, en-têtes masqués.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"utunnel/proto"
)

var (
	serverAddr = flag.String("server", "", "serveur:port (destination réelle après DNAT)")
	pskHex     = flag.String("key", "", "PSK hex (32 octets) — ou fichier via -key-file")
	pskFile    = flag.String("key-file", "", "fichier contenant la clé")
	socksAddr  = flag.String("socks", "127.0.0.1:10080", "écoute SOCKS5 locale")
	maxHops    = flag.Int("hop-port-every", 0, "rotation socket source toutes les N secondes (0 = jamais)")
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
	hop := 0
	if *maxHops > 0 {
		hop = *maxHops
	}

	sess, err := dialTunnel(*serverAddr, psk, hop)
	if err != nil {
		log.Fatalf("établissement tunnel impossible : %v", err)
	}
	log.Printf("tunnel établi vers %s", sess.RemoteAddr())

	// Trafic périodique (toutes les 15 s) : diagnostics "downlink calé à
	// 0B" dans kighmu.txt — montre si les réponses du serveur arrivent
	// réellement (rx = downlink, tx = uplink). pktsIn/pktsBad = vie de la
	// session vs paquets indéchiffrables (PSK, tamper).
	go func() {
		for range time.Tick(15 * time.Second) {
			rx, tx := sess.Stats()
			in, bad := sess.PacketStats()
			log.Printf("trafic: rx=%d B (downlink) tx=%d B (uplink) pkts=%d bad=%d", rx, tx, in, bad)
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
		sess.Close()
		os.Exit(0)
	}()

	for {
		c, err := lsn.Accept()
		if err != nil {
			return
		}
		go handleSOCKS(sess, c)
	}
}

func loadPSK() ([]byte, error) {
	if *pskHex != "" {
		if len(*pskHex) != 64 {
			return nil, errors.New("clé hex doit faire 64 caractères (32 octets)")
		}
		out := make([]byte, 32)
		for i := 0; i < 32; i++ {
			var v int
			fmt.Sscanf((*pskHex)[i*2:i*2+2], "%02x", &v)
			out[i] = byte(v)
		}
		return out, nil
	}
	if *pskFile != "" {
		b, err := os.ReadFile(*pskFile)
		if err != nil {
			return nil, err
		}
		s := strings.TrimSpace(string(b))
		return loadPSKFromString(s)
	}
	return nil, errors.New("--key ou --key-file requis")
}

func loadPSKFromString(s string) ([]byte, error) {
	// Si c'est déjà 64 hex chars (32 octets), on le parse directement
	if len(s) == 64 {
		out := make([]byte, 32)
		for i := 0; i < 32; i++ {
			var v int
			if _, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &v); err != nil {
				return nil, err
			}
			out[i] = byte(v)
		}
		return out, nil
	}
	// Sinon on suppose que c'est le secret brut : on le hache (SHA256) comme le serveur
	sum := sha256.Sum256([]byte(s))
	return sum[:], nil
}

// dialTunnel : handshake + rotation périodique du port source.
func dialTunnel(addr string, psk []byte, hopSec int) (*proto.Session, error) {
	for {
		sess, err := dialOnce(addr, psk)
		if err == nil {
			if hopSec > 0 {
				go hopLoop(addr, psk, hopSec, sess)
			}
			return sess, nil
		}
		// Cause lisible : timeout = AUCUNE réponse du serveur (port fermé,
		// DNAT de plage absent, serveur arrêté, ou PSK invalide côté
		// serveur). Une mauvaise PSK donnerait ErrBadAuth, jamais un
		// silence — le serveur ne répond qu'aux handshakes authentiques.
		log.Printf("dial %s: aucune réponse du serveur (%v) — vérifiez le port, le DNAT de plage et que le serveur tourne — nouvelle tentative dans 2s", addr, err)
		time.Sleep(2 * time.Second)
	}
}

var hopping atomic.Int32

func hopLoop(addr string, psk []byte, sec int, cur *proto.Session) {
	for range time.Tick(time.Duration(sec) * time.Second) {
		if hopping.Load() > 0 {
			continue
		}
		hopping.Add(1)
		// Nouvelle socket source : le serveur suit le pair paquet par
		// paquet, donc la rotation est gratuite (aucun re-handshake).
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err == nil {
			cur.SwapConn(c)
			// Résistance aux pertes du réseau mobile (CGNAT) : un SEUL
			// ping immédiat peut être perdu, et alors le serveur garde
			// l'ancienne adresse de réponse -> downlink mort pour
			// toujours ("downlink calé à 0B" rapporté). On envoie 3
			// pings espacés : le serveur met s.remote à jour au premier
			// qui arrive.
			go func() {
				for i := 0; i < 3; i++ {
					cur.SendKeepalive()
					log.Printf("hop: ping %d/3 nouveau port source %s", i+1, c.LocalAddr())
					time.Sleep(400 * time.Millisecond)
				}
			}()
		}
		hopping.Add(-1)
	}
}

func dialOnce(addr string, psk []byte) (*proto.Session, error) {
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	return proto.NewSession(conn, ra, psk, false)
}

// ── SOCKS5 minimal ───────────────────────────────────────────────────────

func handleSOCKS(sess *proto.Session, c net.Conn) {
	defer c.Close()
	buf := make([]byte, 4096)
	// Greeting
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	nmeth := int(buf[1])
	io.ReadFull(c, buf[:nmeth])
	c.Write([]byte{5, 0}) // pas d'auth

	// Request
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
		socksErr(c, 8)
		return
	}

	switch cmd {
	case 1: // CONNECT
		st, err := sess.Mux().Open(addr)
		if err != nil {
			socksErr(c, 5)
			return
		}
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		bridge(c, st)
	case 3: // UDP ASSOCIATE
		st, err := sess.Mux().OpenUDP()
		if err != nil {
			socksErr(c, 5)
			return
		}
		relayUDPAssociate(c, st)
	default:
		socksErr(c, 7)
	}
}

func socksErr(c net.Conn, code byte) {
	c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}

func bridge(a net.Conn, st *proto.Stream) {
	// ATTENDRE LES DEUX SENS avant de fermer le stream (aligné sur le
	// bridgeTCP du serveur) : fermer à la première fin de sens tronque
	// l'autre — le relais DNS du data plane fait un half-close (CloseWrite
	// après la requête) et la réponse du résolveur serait perdue
	// ("downlink calé à 0B" rapporté).
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(st, a); st.CloseWrite() }()
	go func() { defer wg.Done(); io.Copy(a, st) }()
	wg.Wait()
	st.Close()
}

// relayUDPAssociate : pont SOCKS5-UDP <-> stream "udp:" du tunnel.
// Côté tunnel, chaque frame = [2B len][addr][payload] (chiffré par la session).
func relayUDPAssociate(control net.Conn, st *proto.Stream) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return
	}
	defer uc.Close()

	la := uc.LocalAddr().(*net.UDPAddr)
	ip4 := la.IP.To4()
	hdr := []byte{5, 0, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], byte(la.Port >> 8), byte(la.Port)}
	control.Write(hdr)

	// Mort de la connexion TCP de contrôle => fin du relais.
	go func() {
		io.Copy(io.Discard, control)
		uc.Close()
		st.Close()
	}()

	var clientAddr *net.UDPAddr

	// tunnel -> client SOCKS
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := st.Read(buf)
			if err != nil {
				uc.Close()
				return
			}
			addr, payload := unpackUDPGram(buf[:n])
			if addr == "" || clientAddr == nil {
				continue
			}
			out := socksUDPWrap(addr, payload)
			if out != nil {
				uc.WriteToUDP(out, clientAddr)
			}
		}
	}()

	// client SOCKS -> tunnel
	buf := make([]byte, 4096)
	for {
		n, from, err := uc.ReadFromUDP(buf)
		if err != nil {
			st.Close()
			return
		}
		if clientAddr == nil {
			clientAddr = from
		}
		addr, payload := socksUDPUnwrap(buf[:n])
		if addr == "" || payload == nil {
			continue
		}
		if _, err := st.Write(packUDPGram(addr, payload)); err != nil {
			return
		}
	}
}

// socksUDPUnwrap : retire l'en-tête SOCKS (RSV(2) FRAG(1) ATYP addr port)
// et retourne l'adresse cible + les données.
func socksUDPUnwrap(d []byte) (string, []byte) {
	if len(d) < 4 || d[2] != 0 { // fragments non supportés
		return "", nil
	}
	switch d[3] {
	case 1: // IPv4
		if len(d) < 10 {
			return "", nil
		}
		addr := fmt.Sprintf("%d.%d.%d.%d:%d", d[4], d[5], d[6], d[7], binary.BigEndian.Uint16(d[8:10]))
		return addr, d[10:]
	case 3: // domaine
		if len(d) < 5 {
			return "", nil
		}
		l := int(d[4])
		if len(d) < 5+l+2 {
			return "", nil
		}
		addr := fmt.Sprintf("%s:%d", string(d[5:5+l]), binary.BigEndian.Uint16(d[5+l:5+l+2]))
		return addr, d[5+l+2:]
	case 4: // IPv6
		if len(d) < 22 {
			return "", nil
		}
		addr := fmt.Sprintf("[%s]:%d", net.IP(d[4:20]).String(), binary.BigEndian.Uint16(d[20:22]))
		return addr, d[22:]
	}
	return "", nil
}

// socksUDPWrap : reconstruit un datagramme SOCKS UDP à destination du client.
func socksUDPWrap(addr string, payload []byte) []byte {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	port, _ := strconv.Atoi(portStr)
	var head []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			head = []byte{0, 0, 0, 1, v4[0], v4[1], v4[2], v4[3], byte(port >> 8), byte(port)}
		} else {
			head = append([]byte{0, 0, 0, 4}, ip.To16()...)
			head = append(head, byte(port>>8), byte(port))
		}
	} else {
		head = append([]byte{0, 0, 0, 3, byte(len(host))}, host...)
		head = append(head, byte(port>>8), byte(port))
	}
	return append(head, payload...)
}

func packUDPGram(addr string, payload []byte) []byte {
	out := make([]byte, 0, 2+len(addr)+len(payload))
	out = append(out, byte(len(addr)>>8), byte(len(addr)))
	out = append(out, addr...)
	out = append(out, payload...)
	return out
}

func unpackUDPGram(b []byte) (string, []byte) {
	if len(b) < 2 {
		return "", nil
	}
	l := int(b[0])<<8 | int(b[1])
	if len(b) < 2+l {
		return "", nil
	}
	return string(b[2 : 2+l]), b[2+l:]
}
