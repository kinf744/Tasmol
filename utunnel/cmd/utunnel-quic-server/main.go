package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"utunnel/proto"
)

// ── Serveur utunnel : transport QUIC (quic-go) ─────────────────────────
//
// Le MÊME transport QUIC (quic-go) que le client — compatible garanti.
// Le DPI/CGNAT whitelist le QUIC (indistinguable du HTTPS/3 légitime).
//
// Le protocole :
//   - Le premier stream : [2B len][PSK] → l'auth (le PSK = le secret du
//     users.list OU le hash SHA256(uuid:secret) de la base stivaros) ;
//   - 1 stream bidirectionnel par CONNECT : [2B len][addr][status 1B]
//     puis le bridge bidirectionnel (le TCP target) ;
//   - Les datagrammes QUIC : [2B len][dst][payload] (le relais UDP).

var (
	validMu sync.Mutex
	validM  = map[string]bool{}
)

// Les options nommées (-cc brutal -down-mbps N) — appliquées au relais.
var (
	certFileFlag string
	keyFileFlag  string
	downPacer    *proto.Pacer
)

// Le serveur : les arguments POSITIONNELS historiques (listen, users,
// cert, key) puis les options nommées (-cc brutal -down-mbps N …).
func main() {
	listen := ":5669"
	usersFile := "/etc/utunnel/users.list"
	positional := []string{}
	ccMode := "auto"
	downMbps := 0.0
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-cc":
			if i+1 < len(os.Args) {
				i++
				ccMode = os.Args[i]
			}
		case "-down-mbps":
			if i+1 < len(os.Args) {
				i++
				fmt.Sscanf(os.Args[i], "%f", &downMbps)
			}
		case "-up-mbps":
			if i+1 < len(os.Args) {
				i++
			}
		case "-allow-private":
			allowPrivate = true
		default:
			positional = append(positional, os.Args[i])
		}
	}
	for i, p := range positional {
		switch i {
		case 0:
			listen = p
		case 1:
			usersFile = p
		case 2:
			certFileFlag = p
		case 3:
			keyFileFlag = p
		}
	}
	if ccMode == "brutal" {
		downPacer = proto.NewPacer(downMbps)
		if downPacer == nil {
			logf("brutal sans -down-mbps : pas de pacing (débit cible requis)")
		} else {
			logf("brutal activé : downlink limité à %.0f Mbps", downMbps)
		}
	} else if ccMode != "auto" && ccMode != "" {
		logf("-cc inconnue : %s (auto|brutal) — auto appliqué", ccMode)
	}

	reloadValid(usersFile)
	go func() {
		for range time.Tick(time.Hour) {
			reloadValid(usersFile)
		}
	}()

	// Le cert auto-signé (généré si absent).
	certFile := "/etc/utunnel/quic.crt"
	keyFile := "/etc/utunnel/quic.key"
	if certFileFlag != "" {
		certFile = certFileFlag
	}
	if keyFileFlag != "" {
		keyFile = keyFileFlag
	}
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		genCert(certFile, keyFile)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{loadCert(certFile, keyFile)},
		NextProtos:   []string{"utunnel/1"},
		MinVersion:   tls.VersionTLS13,
	}
	quicCfg := &quic.Config{
		EnableDatagrams: true, // le relais UDP (les datagrammes QUIC)
		MaxIdleTimeout:  30 * time.Second,
	}

	udpAddr, lerr := net.ResolveUDPAddr("udp", listen)
	if lerr != nil {
		fmt.Fprintf(os.Stderr, "[utunnel] listen %s: %v\n", listen, lerr)
		os.Exit(1)
	}
	uconn, uerr := net.ListenUDP("udp", udpAddr)
	if uerr != nil {
		fmt.Fprintf(os.Stderr, "[utunnel] listen %s: %v\n", listen, uerr)
		os.Exit(1)
	}
	pc := proto.NewServerObfsConn(uconn) // les candidates arrivent au premier reloadValid
	tr := &quic.Transport{Conn: pc}
	l, err := tr.ListenEarly(tlsCfg, quicCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[utunnel] listen %s: %v\n", listen, err)
		os.Exit(1)
	}
	logf("utunnel QUIC prêt sur %s", listen)
	go func() {
		for range time.Tick(30 * time.Second) {
			rx, dropped, ok, tx := proto.ObfsStats()
			if rx > 0 || tx > 0 {
				logf("obfs stats: reçus=%d décodés=%d jetés=%d émis=%d", rx, ok, dropped, tx)
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		l.Close()
		os.Exit(0)
	}()

	ctx := context.Background()
	for {
		qconn, err := l.Accept(ctx)
		if err != nil {
			continue
		}
		go handleQUICClient(qconn)
	}
}

func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[utunnel] "+time.Now().Format("2006/01/02 15:04:05 ")+" "+format+"\n", args...)
}

// reloadValid : le users.list (uuid|secret|expire) + les DEUX formats
// (le secret brut ET le hash SHA256(uuid:secret) — les deux acceptés
// comme l'ancien serveur).
func reloadValid(usersFile string) {
	data, err := os.ReadFile(usersFile)
	if err != nil {
		return
	}
	today := time.Now().Format("2006-01-02")
	validMu.Lock()
	defer validMu.Unlock()
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(strings.TrimSpace(line), "|")
		if len(parts) >= 3 && parts[1] != "" && parts[2] >= today {
			validM[parts[1]] = true // le secret brut
			h := sha256.Sum256([]byte(parts[0] + ":" + parts[1]))
			validM[fmt.Sprintf("%x", h)] = true // le hash (l'app le sert)
		}
	}
	// La PSK statique du server.psk (les tests et l'historique).
	if pskData, err := os.ReadFile("/etc/utunnel/server.psk"); err == nil {
		psk := strings.TrimSpace(string(pskData))
		if psk != "" {
			validM[psk] = true
			h := sha256.Sum256([]byte(psk))
			validM[fmt.Sprintf("%x", h)] = true
		}
	}
	logf("PSKs valides rechargées")
	// Les candidates d'obfuscation suivent les PSK (le client dérive la
	// sienne de la PSK que l'API lui sert).
	cands := make([]string, 0, len(validM))
	for k := range validM {
		cands = append(cands, k)
	}
	proto.SetObfsCandidates(cands)
}

func handleQUICClient(qconn quic.Connection) {
	defer func() { _ = recover() }()

	// L'AUTH : le premier stream = [2B len][PSK].
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := qconn.AcceptStream(ctx)
	if err != nil {
		return
	}
	var hdr [2]byte
	if _, err := io.ReadFull(st, hdr[:]); err != nil {
		return
	}
	l := int(hdr[0])<<8 | int(hdr[1])
	if l > 256 {
		return
	}
	psk := make([]byte, l)
	if _, err := io.ReadFull(st, psk); err != nil {
		return
	}
	validMu.Lock()
	ok := validM[string(psk)]
	validMu.Unlock()
	if !ok {
		logf("auth refusée (PSK inconnue)")
		st.Close()
		return
	}
	// L'ACK d'auth : le client attend [1B status=1] sur le stream d'auth
	// (proto.AuthStream lit l'ack après avoir envoyé la PSK). Sans cet
	// octet le client restait bloqué 15 s puis échouait — le tunnel
	// "se connectait" mais le trafic ne passait jamais.
	if _, err := st.Write([]byte{1}); err != nil {
		st.Close()
		return
	}
	logf("auth OK (PSK acceptée)")

	// Le stream d'auth reste ouvert (la session vit tant qu'il vit).
	// Les CONNECT suivants : 1 stream par connexion.
	go handleQUICDatagrams(qconn)
	for {
		cst, err := qconn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleQUICStream(cst)
	}
}

// ── Le relais UDP (les datagrammes QUIC) ────────────────────────────────
//
// Format du datagramme : [2B len][ATYP][addr][port][payload] (l'en-tête
// SOCKS5 UDP sans RSV/FRAG). Le serveur maintient une socket UDP par
// destination (TTL 2 min, plafond par connexion) et relaie les réponses
// au client avec le même en-tête. Les cibles loopback/privées/link-local/
// CGNAT sont refusées (anti-SSRF) sauf -allow-private.

const (
	udpMaxEntries = 256
	udpEntryTTL   = 2 * time.Minute
	udpMaxSize    = 1400
)

var allowPrivate = false

type udpEntry struct {
	conn *net.UDPConn
	last time.Time
}

func socksAddrToUDP(b []byte) (*net.UDPAddr, string, []byte, bool) {
	if len(b) < 2 {
		return nil, "", nil, false
	}
	switch b[0] {
	case 1: // IPv4
		if len(b) < 7 {
			return nil, "", nil, false
		}
		ip := net.IPv4(b[1], b[2], b[3], b[4])
		port := int(b[5])<<8 | int(b[6])
		return &net.UDPAddr{IP: ip, Port: port}, ip.String() + ":" + itoa(port), b[:7], true
	case 4: // IPv6
		if len(b) < 19 {
			return nil, "", nil, false
		}
		ip := net.IP(b[1:17])
		port := int(b[17])<<8 | int(b[18])
		return &net.UDPAddr{IP: ip, Port: port}, ip.String() + ":" + itoa(port), b[:19], true
	case 3: // domaine
		dl := int(b[1])
		if len(b) < 1+1+dl+2 || dl == 0 {
			return nil, "", nil, false
		}
		host := string(b[2 : 2+dl])
		port := int(b[2+dl])<<8 | int(b[2+dl+1])
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, "", nil, false
		}
		return &net.UDPAddr{IP: ips[0], Port: port}, host + ":" + itoa(port), b[:2+dl+2], true
	default:
		return nil, "", nil, false
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	if neg {
		return "-" + string(d)
	}
	return string(d)
}

func isBlockedTarget(addr *net.UDPAddr) bool {
	if allowPrivate {
		return false
	}
	ip := addr.IP
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() || ip.IsMulticast() ||
		(len(ip.To4()) == 4 && ip.To4()[0] == 100 && ip.To4()[1] >= 64 && ip.To4()[1] < 128)
}

func handleQUICDatagrams(qconn quic.Connection) {
	defer func() { _ = recover() }()
	entries := map[string]*udpEntry{}
	defer func() {
		for _, e := range entries {
			e.conn.Close()
		}
	}()
	sweep := time.NewTicker(30 * time.Second)
	defer sweep.Stop()
	for {
		dg, err := qconn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		select {
		case now := <-sweep.C:
			for k, e := range entries {
				if now.Sub(e.last) > udpEntryTTL {
					e.conn.Close()
					delete(entries, k)
				}
			}
		default:
		}
		if len(dg) < 2 {
			continue
		}
		l := int(dg[0])<<8 | int(dg[1])
		if l+2 > len(dg) {
			continue
		}
		inner := dg[2 : 2+l]
		dst, key, hdr, ok := socksAddrToUDP(inner)
		if !ok || dst == nil {
			continue
		}
		if isBlockedTarget(dst) {
			continue
		}
		payload := inner[len(hdr):]
		e := entries[key]
		if e == nil {
			if len(entries) >= udpMaxEntries {
				continue
			}
			rconn, err := net.DialUDP("udp", nil, dst)
			if err != nil {
				continue
			}
			e = &udpEntry{conn: rconn, last: time.Now()}
			entries[key] = e
			go func(e *udpEntry, hdr []byte) {
				rbuf := make([]byte, 65536)
				for {
					n, err := e.conn.Read(rbuf)
					if err != nil {
						return
					}
					if n > udpMaxSize-2-len(hdr) {
						n = udpMaxSize - 2 - len(hdr)
					}
					out := make([]byte, 0, 2+len(hdr)+n)
					total := len(hdr) + n
					out = append(out, byte(total>>8), byte(total))
					out = append(out, hdr...)
					out = append(out, rbuf[:n]...)
					if downPacer != nil {
						downPacer.Wait(len(out))
					}
					if err := qconn.SendDatagram(out); err != nil {
						return
					}
				}
			}(e, append([]byte{}, hdr...))
		}
		e.last = time.Now()
		e.conn.Write(payload)
	}
}

// handleQUICStream : le stream = [2B len][addr] → dial → [status 1B] →
// le bridge bidirectionnel.
func handleQUICStream(st quic.Stream) {
	defer st.Close()
	var hdr [2]byte
	if _, err := io.ReadFull(st, hdr[:]); err != nil {
		return
	}
	l := int(hdr[0])<<8 | int(hdr[1])
	if l > 256 {
		return
	}
	addr := make([]byte, l)
	if _, err := io.ReadFull(st, addr); err != nil {
		return
	}
	target, err := net.DialTimeout("tcp", string(addr), 10*time.Second)
	if err != nil {
		st.Write([]byte{0}) // status 0 = échec
		return
	}
	defer target.Close()
	st.Write([]byte{1}) // status 1 = établi

	done := make(chan struct{}, 2)
	// Downlink (serveur → client) : pacé en mode brutal (l'émetteur décide).
	go func() { io.Copy(target, st); target.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
	go func() { io.Copy(&proto.PacedWriter{W: st, P: downPacer}, target); done <- struct{}{} }()
	<-done
}

// genCert : génère un cert auto-signé si absent (via openssl).
func loadCert(certFile, keyFile string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		logf("loadCert: %v", err)
	}
	return cert
}

func genCert(certFile, keyFile string) {
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyFile, "-out", certFile, "-days", "3650", "-nodes",
		"-subj", "/CN=utunnel.stivaros")
	if err := cmd.Run(); err != nil {
		logf("genCert: %v", err)
	}
}
