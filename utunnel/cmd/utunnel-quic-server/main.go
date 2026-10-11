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

func main() {
	listen := ":5669"
	usersFile := "/etc/utunnel/users.list"
	if len(os.Args) > 1 {
		listen = os.Args[1]
	}
	if len(os.Args) > 2 {
		usersFile = os.Args[2]
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
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		genCert(certFile, keyFile)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{loadCert(certFile, keyFile)},
		NextProtos:   []string{"utunnel/1"},
		MinVersion:   tls.VersionTLS13,
	}
	quicCfg := &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	}

	l, err := quic.ListenAddrEarly(listen, tlsCfg, quicCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[utunnel] listen %s: %v\n", listen, err)
		os.Exit(1)
	}
	logf("utunnel QUIC prêt sur %s", listen)

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
	logf("auth OK (PSK acceptée)")

	// Le stream d'auth reste ouvert (la session vit tant qu'il vit).
	// Les CONNECT suivants : 1 stream par connexion.
	for {
		cst, err := qconn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleQUICStream(cst)
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
	go func() { io.Copy(target, st); target.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
	go func() { io.Copy(st, target); done <- struct{}{} }()
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
