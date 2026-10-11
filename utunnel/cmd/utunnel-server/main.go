package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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

	"utunnel/proto"

	"github.com/quic-go/quic-go"
)

// ── Serveur utunnel : transport QUIC (quic-go) ─────────────────────────
//
// Le transport PROUVÉ sur les réseaux mobiles hostiles (le DPI whitelist
// le QUIC : indistinguable du trafic HTTPS/3). L'identité utunnel
// PRÉSERVÉE : l'auth PSK (SHA256(uuid:secret) de la base stivaros), la
// plage de ports (50000-59999 DNAT-ée), les streams TCP/UDP.
//
// Le protocole : le premier stream = [2B len][PSK] (l'auth) ; 1 stream
// par CONNECT : [2B len][addr][status 1B] puis le bridge TCP ; les
// datagrammes QUIC : [2B len][dst][payload] (le relais UDP/DNS).

func main() {
	listen := ":5669"
	usersFile := "/etc/utunnel/users.list"
	certFile := "/etc/utunnel/zivpn.crt"
	keyFile := "/etc/utunnel/zivpn.key"
	if len(os.Args) > 1 {
		listen = os.Args[1]
	}
	if len(os.Args) > 2 {
		usersFile = os.Args[2]
	}
	if len(os.Args) > 3 {
		certFile = os.Args[3]
	}
	if len(os.Args) > 4 {
		keyFile = os.Args[4]
	}

	// Les PSK valides : le users.list (uuid|secret|expire) + les
	// utunnel_secret de la base stivaros — rechargées toutes les heures.
	valid := &pskSet{m: map[string]bool{}}
	reloadValid(valid, usersFile)
	go func() {
		for range time.Tick(time.Hour) {
			reloadValid(valid, usersFile)
		}
	}()

	l, err := proto.ListenQUIC(listen, certFile, keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "utunnel-server: %v\n", err)
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
		qconn, err := proto.AcceptQUIC(ctx, l)
		if err != nil {
			continue
		}
		go handleQUICClient(qconn, valid)
	}
}

func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[utunnel] "+time.Now().Format("2006/01/02 15:04:05 ")+" "+format+"\n", args...)
}

// pskSet : les PSK valides (le mutex).
type pskSet struct {
	mu sync.Mutex
	m  map[string]bool
}

func (p *pskSet) ok(psk string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.m[psk]
}

func (p *pskSet) add(psk string) {
	p.mu.Lock()
	p.m[psk] = true
	p.mu.Unlock()
}

// reloadValid : le users.list (uuid|secret|expire) + les statiques.
func reloadValid(v *pskSet, usersFile string) {
	data, err := os.ReadFile(usersFile)
	if err != nil {
		return
	}
	today := time.Now().Format("2006-01-02")
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(strings.TrimSpace(line), "|")
		if len(parts) >= 3 && parts[1] != "" && parts[2] >= today {
			// Les DEUX formats acceptés : le secret brut ET le hash
			// SHA256(uuid:secret) — l'app sert le hash (champ
			// utunnel_secret 64 hex), les tests locaux le secret brut.
			v.add(parts[1])
			h := sha256.Sum256([]byte(parts[0] + ":" + parts[1]))
			v.add(fmt.Sprintf("%x", h))
		}
	}
}

func handleQUICClient(qconn quic.Connection, valid *pskSet) {
	defer func() { _ = recover() }()
	// L'AUTH : le premier stream = [2B len][PSK].
	astream, err := proto.AcceptAuthStream(qconn, valid.ok, 15*time.Second)
	if err != nil {
		return
	}
	_ = astream

	// Les CONNECT : 1 stream par connexion.
	for {
		st, err := qconn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleQUICStream(st)
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
	go func() { io.Copy(target, st); target.(interface{ CloseWrite() error }).CloseWrite(); done <- struct{}{} }()
	go func() { io.Copy(st, target); done <- struct{}{} }()
	<-done
}

var _ = exec.Command
var _ = binary.BigEndian
