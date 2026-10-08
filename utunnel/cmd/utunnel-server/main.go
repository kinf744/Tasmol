// utunnel-server : endpoint du tunnel UDP utunnel.
//
//   - authentification par clé partagée (--key / fichier) + X25519 éphémère ;
//   - une socket UDP unique ; toute une PLAGE de ports peut être renvoyée
//     dessus par DNAT nftables (utunnel suit l'adresse:port du pair à chaque
//     paquet, donc le port-hopping client marche nativement) ;
//   - multi-sessions, multiplexage TCP + relais UDP via proto.Mux ;
//   - expirations par compte (mode stivaros: fichier users.list username|pass|YYYY-MM-DD
//     optionnel : chaque clé PSK = SHA256(username:pass), purge quotidienne).
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"utunnel/proto"
)

var (
	listenAddr = flag.String("listen", ":5900", "Adresse d'écoute UDP")
	pskFile    = flag.String("key-file", "/etc/utunnel/server.psk", "Fichier de clé PSK (une ligne)")
	usersFile  = flag.String("users-file", "", "users.list stivaros: uuid|secret|expire (optionnel)")
	maxSess    = flag.Int("max-sessions", 4096, "Sessions simultanées max")
	verbose    = flag.Bool("v", false, "Logs verbeux")
)

type pskSet struct {
	mu   sync.RWMutex
	psks map[string]struct{} // hex(sha256) du secret
}

// candidates retourne les clés candidates en clair (essai handshake1).
func (p *pskSet) candidates() [][]byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([][]byte, 0, len(p.psks))
	for h := range p.psks {
		out = append(out, unhex(h))
	}
	return out
}

func (p *pskSet) loadStatic(file string) (string, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	k := strings.TrimSpace(string(b))
	sum := sha256.Sum256([]byte(k))
	p.mu.Lock()
	p.psks = map[string]struct{}{fmt.Sprintf("%x", sum): {}}
	p.mu.Unlock()
	return fmt.Sprintf("%x", sum), nil
}

func (p *pskSet) loadUsers(file string) int {
	b, err := os.ReadFile(file)
	if err != nil {
		return 0
	}
	today := time.Now().Format("2006-01-02")
	fresh := map[string]struct{}{}
	// La clé statique est préservée
	p.mu.RLock()
	for k := range p.psks {
		fresh[k] = struct{}{}
	}
	p.mu.RUnlock()

	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Split(line, "|")
		if len(parts) < 3 || parts[1] == "" || parts[2] < today {
			continue
		}
		// DEUX dérivations acceptées par entrée :
		//   1. SHA256(uuid:secret) — la formule historique stivaros, servie
		//      pré-calculée par l'API (champ utunnel_secret, 64 hex) ;
		//   2. SHA256(secret) seul — le client app (resolveClientKey) ne
		//      connaît PAS l'uuid du compte : un profil configuré à la main
		//      avec le secret brut dérivait SHA256(secret) et le serveur le
		//      rejetait en silence (dial timeout, aucun log). L'app doit
		//      marcher telle quelle avec la valeur affichée par le panel.
		sum := sha256.Sum256([]byte(parts[0] + ":" + parts[1]))
		fresh[fmt.Sprintf("%x", sum)] = struct{}{}
		sum2 := sha256.Sum256([]byte(parts[1]))
		fresh[fmt.Sprintf("%x", sum2)] = struct{}{}
	}
	p.mu.Lock()
	p.psks = fresh
	n := len(fresh)
	p.mu.Unlock()
	return n
}

func unhex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := 0; i+2 <= len(s); i += 2 {
		var v int
		fmt.Sscanf(s[i:i+2], "%02x", &v)
		out[i/2] = byte(v)
	}
	return out
}

func main() {
	flag.Parse()
	log.SetPrefix("[utunnel] ")

	psks := &pskSet{psks: map[string]struct{}{}}
	if _, err := psks.loadStatic(*pskFile); err != nil {
		log.Fatalf("clé statique introuvable (crée %s avec un secret) : %v", *pskFile, err)
	}
	if *usersFile != "" {
		n := psks.loadUsers(*usersFile)
		log.Printf("users.list : %d clés actives", n)
		go func() { // rechargement horaire (expiration quotidienne)
			for range time.Tick(time.Hour) {
				psks.loadUsers(*usersFile)
			}
		}()
	}

	addr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	log.Printf("utunnel prêt sur %s (UDP, range-DNAT compatible)", conn.LocalAddr())

	// Démultiplexage : token de session (8 premiers octets du fil)
	var mu sync.RWMutex
	sessions := map[[16]byte]*proto.Session{} // token wire → session
	hsSem := make(chan struct{}, 64)          // limite les handshakes concurrents
	hsReg := proto.NewHandshakeRegistry()     // dédup réémissions h1 + réémission h2

	count := func() int { mu.RLock(); defer mu.RUnlock(); return len(sessions) }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		conn.Close()
		os.Exit(0)
	}()

	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		raw := buf[:n]

		// Paquet de session existante ? (token masqué = 8 premiers octets)
		if n >= proto.MinPktLen {
			mu.RLock()
			sess, ok := lookup16(sessions, raw[:8])
			mu.RUnlock()
			if ok {
				sess.HandleFromServer(from, append([]byte(nil), raw...))
				continue
			}
		}

		// Sinon : tentative de handshake1 (limitée en concurrence et en
		// nombre total de sessions — anti-flood). Les réémissions du même
		// h1 sont dédupliquées par le registre (réémission h2, aucune
		// nouvelle session).
		if n >= proto.PreKeyLen && n <= proto.PreKeyLen+64 {
			if count() >= *maxSess {
				continue
			}
			select {
			case hsSem <- struct{}{}:
			default:
				continue // saturation : on ignore, le client réessaie
			}
			go func() {
				defer func() { <-hsSem }()
				hsReg.Try(conn, from, append([]byte(nil), raw...), psks.candidates(), func(s *proto.Session) {
					w := s.WireToken()
					var k [16]byte
					copy(k[:], w[:])
					mu.Lock()
					sessions[k] = s
					mu.Unlock()
					log.Printf("session +%s (total=%d)", from, count())
					go runSessionMux(s, func() {
						mu.Lock()
						delete(sessions, k)
						mu.Unlock()
						log.Printf("session -%s (total=%d)", from, count())
					})
				})
			}()
		}
	}
}

func lookup16(m map[[16]byte]*proto.Session, wire8 []byte) (*proto.Session, bool) {
	var k [16]byte
	copy(k[:], wire8)
	s, ok := m[k]
	return s, ok
}

// runSessionMux accepte les streams entrants et les pontille.
func runSessionMux(s *proto.Session, onDead func()) {
	defer onDead()
	mux := s.Mux()
	mux.SetDialer(
		func(addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.Dial("tcp", addr)
		},
		func(st *proto.Stream) { // relais UDP : chaque frame = datagramme
			go udpRelay(st)
		},
	)
	// Le Serveur ne fait rien avec Accept() : SetDialer couvre tout.
	// Accept est tout de même disponible pour extensions futures.
	for {
		if _, err := mux.Accept(); err != nil {
			return
		}
	}
}

// udpRelay : payloads = [2B addrLen][addr][2B port][données] chiffrés.
func udpRelay(st *proto.Stream) {
	up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		st.Close()
		return
	}
	defer up.Close()
	go func() { // réponses -> client
		buf := make([]byte, 2048)
		for {
			n, from, err := up.ReadFromUDP(buf)
			if err != nil {
				return
			}
			frame := packUDPGram(from.String(), buf[:n])
			if _, err := st.Write(frame); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 2048)
	for {
		n, err := st.Read(buf)
		if err != nil {
			return
		}
		addr, payload := unpackUDPGram(buf[:n])
		da, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			continue
		}
		up.WriteToUDP(payload, da)
	}
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
