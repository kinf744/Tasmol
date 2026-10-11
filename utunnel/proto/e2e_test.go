package proto

import (
	"bytes"
	"crypto/rand"
	"io"
	mrand "math/rand"
	"net"
	"testing"
	"time"
)

var testPSK = bytes.Repeat([]byte{0xA5}, 32)

// ── Paquet : chiffrement/déchiffrement, tamper, AAD ──────────────────────

func TestPacketRoundtrip(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])
	var token [tokenLen]byte
	copy(token[:], "tok12345")

	payload := []byte("hello utunnel — payload de test")
	pkt := encodePacket(&key, &token, TypeData, 0x7, 1234, 42, 7, 0xFF00FF00, payload)
	if len(pkt) != tokenLen+nonceLen+aeadOver+hdrLen+len(payload) {
		t.Fatalf("taille inattendue: %d", len(pkt))
	}

	typ, flags, wnd, seq, ack, bits, got, err := decodePacket(&key, pkt)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if typ != TypeData || flags != 0x7 || wnd != 1234 || seq != 42 || ack != 7 || bits != 0xFF00FF00 {
		t.Fatalf("en-tête mal restitué: %v %v %v %v %v %v", typ, flags, wnd, seq, ack, bits)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mal restitué")
	}

	// Mauvaise clé → rejet
	if _, _, _, _, _, _, _, err := decodePacket(&key, append([]byte(nil), pkt...)); err != nil {
		_ = err
	}
	var wrong [32]byte
	rand.Read(wrong[:])
	if _, _, _, _, _, _, _, err := decodePacket(&wrong, pkt); err == nil {
		t.Fatal("déchiffrement avec mauvaise clé doit échouer")
	}

	// Tamper 1 octet au milieu → rejet
	tam := append([]byte(nil), pkt...)
	tam[len(tam)/2] ^= 0xFF
	if _, _, _, _, _, _, _, err := decodePacket(&key, tam); err == nil {
		t.Fatal("paquet altéré doit être rejeté (AEAD)")
	}

	// AAD (token) modifié → rejet
	tok2 := append([]byte(nil), pkt...)
	tok2[3] ^= 0x01
	if _, _, _, _, _, _, _, err := decodePacket(&key, tok2); err == nil {
		t.Fatal("token altéré doit être rejeté (AAD)")
	}
}

// ── Handshake : validité, mauvaise clé, rejeu temporel ───────────────────

func TestHandshakeRoundtrip(t *testing.T) {
	_, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().Unix()
	h1 := BuildHandshake1(testPSK[:], &pub, ts)
	if len(h1) != PreKeyLen {
		t.Fatalf("h1=%d attendu %d", len(h1), PreKeyLen)
	}

	eph, err := ParseHandshake1(testPSK[:], h1, ts)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if eph != pub {
		t.Fatal("ephPub mal restitué")
	}

	// Mauvaise clé → ErrBadAuth
	badPSK := bytes.Repeat([]byte{0x5A}, 32)
	if _, err := ParseHandshake1(badPSK[:], h1, ts); err != ErrBadAuth {
		t.Fatalf("attendu ErrBadAuth, eu %v", err)
	}

	// Horodatage périmé → ErrSessExpired
	if _, err := ParseHandshake1(testPSK[:], h1, ts-600); err != ErrSessExpired {
		t.Fatalf("attendu ErrSessExpired, eu %v", err)
	}

	// Confirm dérivable identiquement des deux côtés
	priv, _, _ := GenerateKeypair()
	shared1, _ := dh(&priv, &eph)
	keys := deriveKeys(&shared1, testPSK[:])
	c1 := HandshakeConfirm(&keys.C2S, &eph)
	if len(c1) != 16 {
		t.Fatal("confirm 16B")
	}
}

// ── Session complète : handshake UDP réel + TCP proxy + UDP stream ───────

// startTCPEcho lance un serveur d'écho TCP local.
func startTCPEcho(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Boucle manuelle : io.Copy(c, c) emprunte le fast-path splice
			// de Go qui se bloque lorsque src == dst (même socket).
			go func(c net.Conn) {
				buf := make([]byte, 16384)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							break
						}
					}
					if err != nil {
						c.Close()
						return
					}
				}
				c.Close()
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestSessionE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e long")
	}
	echoAddr := startTCPEcho(t)

	// Socket serveur
	sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	saddr := sconn.LocalAddr().(*net.UDPAddr)

	// Handshake client en parallèle (bloquant jusqu'à handshake2)
	type res struct {
		s   *Session
		err error
	}
	ch := make(chan res, 1)
	go func() {
		cconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			ch <- res{nil, err}
			return
		}
		s, err := NewSession(cconn, saddr, testPSK[:], false)
		ch <- res{s, err}
	}()

	// Côté serveur : lit handshake1, répond, démarre la session
	hbuf := make([]byte, 512)
	sconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := sconn.ReadFromUDP(hbuf)
	if err != nil {
		t.Fatalf("lecture h1: %v", err)
	}
	ephPub, err := ParseHandshake1(testPSK[:], hbuf[:n], time.Now().Unix())
	if err != nil {
		t.Fatalf("parse h1: %v", err)
	}
	srv, err := RespondHandshake(sconn, from, testPSK[:], &ephPub)
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	sconn.SetReadDeadline(time.Time{})

	// Mux serveur : dialer TCP réel + écho UDP applicatif
	srv.Mux().SetDialer(
		func(addr string) (net.Conn, error) { return net.Dial("tcp", addr) },
		func(st *Stream) { // écho applicatif du stream UDP
			go func() {
				buf := make([]byte, 4096)
				for {
					nr, err := st.Read(buf)
					if err != nil {
						return
					}
					if _, err := st.Write(buf[:nr]); err != nil {
						return
					}
				}
			}()
		},
	)

	// Démultiplexeur serveur (rôle joué par main.go en production)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := sconn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			srv.HandleFromServer(from, buf[:n])
		}
	}()

	r := <-ch
	if r.err != nil {
		t.Fatalf("handshake client: %v", r.err)
	}
	cli := r.s
	defer cli.Close()

	// 1) Petit aller-retour TCP via le tunnel
	st, err := cli.Mux().Open(echoAddr)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	msg := []byte("ping-utunnel-0")
	if _, err := st.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo incohérent: %q", got)
	}

	// 2) Gros transfert (1 Mo) : ARQ, fenêtre, réordonnancement
	big := make([]byte, 1<<20)
	rand.Read(big)
	go func() {
		if _, err := st.Write(big); err != nil {
			t.Errorf("write big: %v", err)
		}
		st.CloseWrite()
	}()
	echoed, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if !bytes.Equal(echoed, big) {
		t.Fatalf("écho 1Mo incohérent: %d bytes reçues", len(echoed))
	}
	st.Close()

	// 3) Stream UDP : écho applicatif
	us, err := cli.Mux().OpenUDP()
	if err != nil {
		t.Fatalf("open udp: %v", err)
	}
	dg := []byte("datagramme-udp-01")
	if _, err := us.Write(dg); err != nil {
		t.Fatalf("write udp: %v", err)
	}
	back := make([]byte, 64)
	us.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := us.Read(back); err != nil {
		t.Fatalf("read udp: %v", err)
	}
	if !bytes.Equal(back[:len(dg)], dg) {
		t.Fatalf("écho udp incohérent")
	}
	us.Close()

	// 4) Statistiques basiques de session
	cli.mu.Lock()
	inflight := len(cli.unacked)
	cli.mu.Unlock()
	if inflight != 0 {
		t.Fatalf("segments restés en vol après transfert: %d", inflight)
	}
}

// ── Résistance aux pertes : 15 % de paquets jetés dans chaque sens ───────

// startLossyProxy intercale un relais UDP qui abandonne dropRatio des
// paquets (les deux sens) entre le client et target.
func startLossyProxy(t *testing.T, target *net.UDPAddr, dropRatio float64) *net.UDPAddr {
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	var client *net.UDPAddr

	drop := func() bool { return mrand.Float64() < dropRatio }

	go func() { // client -> serveur
		buf := make([]byte, 4096)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			client = from
			if drop() {
				continue
			}
			back.WriteToUDP(buf[:n], target)
		}
	}()
	go func() { // serveur -> client
		buf := make([]byte, 4096)
		for {
			n, _, err := back.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if drop() || client == nil {
				continue
			}
			front.WriteToUDP(buf[:n], client)
		}
	}()
	return front.LocalAddr().(*net.UDPAddr)
}

func TestSessionWithLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e long")
	}
	echoAddr := startTCPEcho(t)

	sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := startLossyProxy(t, sconn.LocalAddr().(*net.UDPAddr), 0.15)

	type res struct {
		s   *Session
		err error
	}
	ch := make(chan res, 1)
	go func() {
		cconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			ch <- res{nil, err}
			return
		}
		s, err := NewSession(cconn, proxyAddr, testPSK[:], false)
		ch <- res{s, err}
	}()

	// Côté serveur : le premier handshake1 est validé via le registre (les
	// réémissions suivantes réemètrent le même handshake2), puis le
	// démultiplexeur route paquets de session / h1 réémis.
	hbuf := make([]byte, 512)
	sconn.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, from, err := sconn.ReadFromUDP(hbuf)
	if err != nil {
		t.Fatalf("lecture h1: %v", err)
	}
	reg := NewHandshakeRegistry()
	var srv *Session
	reg.Try(sconn, from, append([]byte(nil), hbuf[:n]...), [][]byte{testPSK[:]},
		func(s *Session) { srv = s })
	if srv == nil {
		t.Fatal("handshake1 non authentifié")
	}
	sconn.SetReadDeadline(time.Time{})
	srv.Mux().SetDialer(
		func(addr string) (net.Conn, error) { return net.Dial("tcp", addr) },
		nil,
	)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := sconn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			raw := append([]byte(nil), buf[:n]...)
			// Paquet de session ? (déchiffrable avec les clés serveur)
			if _, _, _, _, _, _, _, derr := decodePacket(&srv.rxKey, raw); derr == nil {
				srv.HandleFromServer(from, raw)
				continue
			}
			// Sinon : handshake1 (réémission incluse) — paddé à 1300 B
			// (le padding QUIC 1200+).
			if n >= PreKeyLen && n <= PreKeyLen+1400 {
				reg.Try(sconn, from, raw, [][]byte{testPSK[:]}, nil)
			}
		}
	}()

	r := <-ch
	if r.err != nil {
		t.Fatalf("handshake client (avec pertes): %v", r.err)
	}
	cli := r.s
	defer cli.Close()

	st, err := cli.Mux().Open(echoAddr)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// 256 Ko à travers 15% de pertes : l'ARQ doit tout récupérer.
	big := make([]byte, 256<<10)
	rand.Read(big)
	go func() {
		if _, err := st.Write(big); err != nil {
			t.Errorf("write: %v", err)
		}
		st.CloseWrite()
	}()
	echoed, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if !bytes.Equal(echoed, big) {
		t.Fatalf("écho 256Ko incohérent avec pertes: %d/%d", len(echoed), len(big))
	}
}
