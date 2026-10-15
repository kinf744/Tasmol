package proto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20"
)

// ── L'obfuscation des paquets UDP (anti-DPI / anti-CGNAT) ───────────────
//
// Le QUIC nu sur un port haut se fait classifier et tuer par le DPI des
// réseaux mobiles : le handshake (paquets paddés 1200 B, indistinguables
// du HTTPS/3) passe, puis les paquets de données — PETITS — sont bloqués
// ("flood petits paquets UDP"), et le tunnel meurt juste après
// l'établissement. C'est exactement ce qui a tué l'ARQ propriétaire et ce
// que le zivpn/Hysteria contourne avec l'obfs salamander.
//
// La couche ici : chaque paquet UDP est réécrit en
//
//	[12B nonce][chacha20(key, nonce) : [2B realLen]["UTN1"][données][pad aléatoire]]
//
// — le chacha20 rend les paquets indistinguables d'un bruit aléatoire ;
// — le padding aléatoire gomme les tailles (les paquets de contrôle
//   minuscules du QUIC ressortent à taille pleine) ;
// — la clé est DÉRIVÉE de la PSK (zéro configuration) : le client connaît
//   la sienne, le serveur essaie les candidates issues du users.list —
//   le magic "UTN1" identifie la bonne clé sans ambiguïté, et la clé
//   apprise est réutilisée pour sceller les réponses.

const (
	obfsMagic    = "UTN1"
	obfsOverhead = 12 + 2 + 4 // nonce 12 (chacha20) + realLen + magic
	obfsMaxTotal = 1350
	obfsLearnCap = 512
)

type obfsKey [32]byte

func deriveObfsKey(psk string) obfsKey {
	return sha256.Sum256([]byte("utunnel-obfs-v1:" + psk))
}

// obfsCandidates : les clés candidates côté serveur (une par PSK du
// users.list), mises à jour à chaque reloadValid. Le client n'en a qu'une.
var (
	obfsMu   sync.Mutex
	obfsKeys []obfsKey
)

// SetObfsCandidates : (re)charge les clés candidates du serveur.
func SetObfsCandidates(psks []string) {
	setObfsCandidates(psks)
}

func setObfsCandidates(psks []string) {
	obfsMu.Lock()
	defer obfsMu.Unlock()
	obfsKeys = obfsKeys[:0]
	seen := map[string]bool{}
	for _, p := range psks {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		obfsKeys = append(obfsKeys, deriveObfsKey(p))
	}
}

func obfsCandidateKeys() []obfsKey {
	obfsMu.Lock()
	defer obfsMu.Unlock()
	return append([]obfsKey{}, obfsKeys...)
}

// ObfsDebugHook : instrumentation temporaire (nil en prod calme).
var ObfsDebugHook func(dir string, n int, addr net.Addr, first byte)

// sealObfs : réécrit b en paquet obfusqué (pad aléatoire, taille gommée).
func sealObfs(key obfsKey, b []byte) []byte {
	if len(b) > obfsMaxTotal-obfsOverhead {
		// Trop gros pour le PMTU assuré : tronqué (le QUIC s'en remet).
		b = b[:obfsMaxTotal-obfsOverhead]
	}
	var nonce [12]byte
	_, _ = rand.Read(nonce[:])
	realLen := len(b)
	padSpan := obfsMaxTotal - obfsOverhead - realLen
	padLen := 16
	if padSpan > 16 {
		var r [2]byte
		_, _ = rand.Read(r[:])
		padLen = 16 + int(binary.BigEndian.Uint16(r[:]))%(padSpan-16+1)
	}
	total := realLen + 4 + padLen
	plain := make([]byte, total)
	binary.BigEndian.PutUint16(plain[:2], uint16(realLen))
	copy(plain[2:6], obfsMagic)
	copy(plain[6:], b)
	_, _ = rand.Read(plain[6+realLen : total])
	ciph, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return nil
	}
	out := make([]byte, len(nonce)+len(plain))
	copy(out, nonce[:])
	ciph.XORKeyStream(out[len(nonce):], plain)
	return out
}

// openObfs : décode un paquet avec UNE clé. nil si la clé n'est pas la
// bonne (le magic "UTN1" rejette les faux positifs à 1/2^32).
func openObfs(key obfsKey, b []byte) []byte {
	if len(b) < obfsOverhead+6 {
		return nil
	}
	var nonce [12]byte
	copy(nonce[:], b[:12])
	body := make([]byte, len(b)-12)
	ciph, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return nil
	}
	ciph.XORKeyStream(body, b[12:])
	realLen := int(binary.BigEndian.Uint16(body[:2]))
	if realLen+6 > len(body) {
		return nil
	}
	if string(body[2:6]) != obfsMagic {
		return nil
	}
	return body[6 : 6+realLen]
}

// Compteurs de diagnostic (lus par le serveur toutes les 30 s).
var (
	obfsRxPackets uint64 // paquets UDP reçus
	obfsRxDropped uint64 // paquets reçus mais indécodables (aucune clé)
	obfsRxOK      uint64 // paquets décodés
	obfsTxPackets uint64 // paquets scellés émis
)

func ObfsStats() (rx, dropped, ok, tx uint64) {
	return atomic.LoadUint64(&obfsRxPackets), atomic.LoadUint64(&obfsRxDropped),
		atomic.LoadUint64(&obfsRxOK), atomic.LoadUint64(&obfsTxPackets)
}

// ObfsPacketConn : un net.PacketConn qui (dés)obfusque à la volée.
//   - Client : NewClientObfsConn (une clé fixe, dérivée de la PSK) ;
//   - Serveur : NewServerObfsConn (essai de toutes les candidates par
//     paquet ; la clé de chaque pair est apprise et sert au downlink).
type ObfsPacketConn struct {
	net.PacketConn
	clientKey *obfsKey

	mu      sync.Mutex
	learned map[string]obfsKey
}

func NewClientObfsConn(pc net.PacketConn, key obfsKey) *ObfsPacketConn {
	return &ObfsPacketConn{PacketConn: pc, clientKey: &key, learned: map[string]obfsKey{}}
}

func NewServerObfsConn(pc net.PacketConn) *ObfsPacketConn {
	return &ObfsPacketConn{PacketConn: pc, learned: map[string]obfsKey{}}
}

func (c *ObfsPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	var key *obfsKey
	if c.clientKey != nil {
		key = c.clientKey
	} else {
		c.mu.Lock()
		k, ok := c.learned[addr.String()]
		c.mu.Unlock()
		if !ok {
			k = obfsCandidateKeys()[0]
		}
		key = &k
	}
	atomic.AddUint64(&obfsTxPackets, 1)
	out := sealObfs(*key, b)
	if ObfsDebugHook != nil && len(b) > 0 {
		ObfsDebugHook("tx", len(b), addr, b[0])
	}
	return c.PacketConn.WriteTo(out, addr)
}

func (c *ObfsPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		raw := make([]byte, 65536)
		n, addr, err := c.PacketConn.ReadFrom(raw)
		if err != nil {
			return 0, addr, err
		}
		raw = raw[:n]
		atomic.AddUint64(&obfsRxPackets, 1)
		if c.clientKey != nil {
			if data := openObfs(*c.clientKey, raw); data != nil {
				atomic.AddUint64(&obfsRxOK, 1)
				return copy(b, data), addr, nil
			}
			atomic.AddUint64(&obfsRxDropped, 1)
			continue
		}
		for _, k := range obfsCandidateKeys() {
			if data := openObfs(k, raw); data != nil {
				atomic.AddUint64(&obfsRxOK, 1)
				if ObfsDebugHook != nil && len(data) > 0 {
					ObfsDebugHook("rx", len(data), addr, data[0])
				}
				c.mu.Lock()
				if len(c.learned) >= obfsLearnCap {
					c.learned = map[string]obfsKey{}
				}
				c.learned[addr.String()] = k
				c.mu.Unlock()
				return copy(b, data), addr, nil
			}
		}
		atomic.AddUint64(&obfsRxDropped, 1)
		// Bruit internet ou clé inconnue : silencieusement jeté.
	}
}
