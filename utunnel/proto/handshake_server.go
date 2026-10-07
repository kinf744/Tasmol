package proto

import (
	"net"
	"sync"
	"time"
)

// ── Côté serveur : dédup des handshakes + réémission handshake2 ──────────
//
// Le client réémet handshake1 (pertes du lien) tant que handshake2 n'est
// pas reçu. Sans dédup, chaque réémission créerait une session complète
// (nouvelles clés + mux) jamais utilisée — fuite de sessions et double
// pont. Le registre indexe les sessions établies par ephémère client :
// une réémission retransmit le MÊME handshake2 (mêmes clés, aucun
// re-handshake, aucune nouvelle session).

const hsRegTTL = 5 * time.Minute

type hsEntry struct {
	sess *Session
	h2   []byte
	at   time.Time
}

type HandshakeRegistry struct {
	mu    sync.Mutex
	byEph map[[32]byte]*hsEntry
}

func NewHandshakeRegistry() *HandshakeRegistry {
	return &HandshakeRegistry{byEph: map[[32]byte]*hsEntry{}}
}

// Try valide handshake1 contre les PSK candidates. Un h1 authentique déjà
// vu (réémission) → retransmission du handshake2 stocké ; nouveau h1
// authentique → réponse + onNew(sess). Silencieux sur h1 invalide — le
// serveur ne répond qu'aux handshakes authentiques.
func (r *HandshakeRegistry) Try(conn *net.UDPConn, from *net.UDPAddr, raw []byte, psks [][]byte, onNew func(*Session)) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, e := range r.byEph {
		if now.Sub(e.at) > hsRegTTL {
			delete(r.byEph, k)
		}
	}
	ts := now.Unix()
	for _, psk := range psks {
		eph, err := ParseHandshake1(psk, raw, ts)
		if err != nil {
			continue
		}
		if e, ok := r.byEph[eph]; ok {
			_, _ = conn.WriteToUDP(e.h2, from)
			return
		}
		sess, h2, err := respondHandshakeH2(conn, from, psk, &eph)
		if err != nil {
			return
		}
		r.byEph[eph] = &hsEntry{sess: sess, h2: h2, at: now}
		if onNew != nil {
			onNew(sess)
		}
		return
	}
}
