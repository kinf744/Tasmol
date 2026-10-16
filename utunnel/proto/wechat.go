package proto

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20"
)

const (
	obfsMagic    = "UTN1"
	obfsOverhead = 12 + 2 + 4 // nonce 12 (chacha20) + realLen + magic
	// obfsFixedTotal : la TAILLE FIXE sur le câble (l'enveloppe WeChat
	// incluse) — le profil filaire exact du zivpn qui passe.
	obfsFixedTotal = 1447
)

func sha256Sum(b []byte) [32]byte {
	return sha256.Sum256(b)
}

func chacha20New(key, nonce []byte) (*chacha20.Cipher, error) {
	return chacha20.NewUnauthenticatedCipher(key, nonce)
}

// ── L'enveloppe WeChat (à la hysteria v1 pktconns/wechat) ───────────────
//
// Les CGNAT des opérateurs africains filtrent l'UDP non reconnu mais
// WHITELISTENT les paquets vocaux WeChat (l'app n°1 : ils les optimisent
// au lieu de les filtrer). Chaque paquet UDP est enveloppé dans un
// en-tête d'appel vidéo WeChat de 13 octets — le portage direct de
// hysteria v1 (MIT) — avec NOTRE obfs chacha20 dedans :
//
//	[0]=0xa1 [1]=0x08 [2..5]=sn BE32 incrémental [6]=0x00 [7]=0x10
//	[8]=0x11 [9]=0x18 [10]=0x30 [11]=0x22 [12]=0x30
//	[13..]=sealObfs(p) = [12B nonce][chacha20: [2B len]["UTN1"][data][pad]]
//
// Le DPI voit un paquet vocal WeChat banal (le profil filaire exact du
// zivpn qui passe) ; le contenu sous l'enveloppe reste chiffré.

const (
	wechatHeaderLen = 13
)

// Compteurs de diagnostic (le serveur les logue toutes les 30 s).
var (
	obfsRxPackets uint64
	obfsRxDropped uint64
	obfsRxOK      uint64
	obfsTxPackets uint64
)

func ObfsStats() (rx, dropped, ok, tx uint64) {
	return atomic.LoadUint64(&obfsRxPackets), atomic.LoadUint64(&obfsRxDropped),
		atomic.LoadUint64(&obfsRxOK), atomic.LoadUint64(&obfsTxPackets)
}

type obfsKey [32]byte

func deriveObfsKey(psk string) obfsKey {
	return sha256Sum([]byte("utunnel-obfs-v1:" + psk))
}

// obfsCandidates : les clés candidates côté serveur (une par PSK du
// users.list), mises à jour à chaque reloadValid.
var (
	obfsMu   sync.Mutex
	obfsKeys []obfsKey
)

func SetObfsCandidates(psks []string) {
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

// sealObfs : réécrit b en paquet obfusqué — TAILLE FIXE (le profil
// filaire du zivpn qui passe), contenu chiffré + paddé aléatoirement.
func sealObfs(key obfsKey, b []byte) []byte {
	if len(b) > obfsFixedTotal-obfsOverhead {
		b = b[:obfsFixedTotal-obfsOverhead]
	}
	var nonce [12]byte
	_, _ = rand.Read(nonce[:])
	realLen := len(b)
	padLen := obfsFixedTotal - obfsOverhead - 4 - realLen
	if padLen < 0 {
		padLen = 0
	}
	total := realLen + 4 + padLen
	plain := make([]byte, total)
	binary.BigEndian.PutUint16(plain[:2], uint16(realLen))
	copy(plain[2:6], obfsMagic)
	copy(plain[6:], b)
	_, _ = rand.Read(plain[6+realLen : total])
	ciph, err := chacha20New(key[:], nonce[:])
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
	ciph, err := chacha20New(key[:], nonce[:])
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

// WeChatPacketConn : un net.PacketConn qui (1) enveloppe chaque paquet
// dans l'en-tête d'appel vidéo WeChat et (2) chiffre la charge avec
// notre obfs. Client : une clé fixe (dérivée de la PSK) ; Serveur :
// essai des candidates par paquet + la clé apprise par IP pour le
// downlink (le CGNAT tourne les ports, pas les IP).
type WeChatPacketConn struct {
	inner net.PacketConn
	keys  []obfsKey // client : 1 ; serveur : les candidates

	mu         sync.Mutex
	learned    map[string]obfsKey // serveur : ip -> clé
	writeBuf   []byte
	readBuf    []byte
	writeMutex sync.Mutex
	readMutex  sync.Mutex
	sn         uint32
}

func NewClientWeChatConn(pc net.PacketConn, key obfsKey) *WeChatPacketConn {
	return &WeChatPacketConn{
		inner:    pc,
		keys:     []obfsKey{key},
		learned:  map[string]obfsKey{},
		writeBuf: make([]byte, 65536),
		readBuf:  make([]byte, 65536),
		sn:       rand.Uint32() & 0xFFFF,
	}
}

func NewServerWeChatConn(pc net.PacketConn) *WeChatPacketConn {
	return &WeChatPacketConn{
		inner:    pc,
		learned:  map[string]obfsKey{},
		writeBuf: make([]byte, 65536),
		readBuf:  make([]byte, 65536),
		sn:       rand.Uint32() & 0xFFFF,
	}
}

func ipOf(addr net.Addr) string {
	if ua, ok := addr.(*net.UDPAddr); ok {
		return ua.IP.String()
	}
	return addr.String()
}

func (c *WeChatPacketConn) sealFor(addr net.Addr) obfsKey {
	if len(c.keys) == 1 {
		return c.keys[0]
	}
	c.mu.Lock()
	k, ok := c.learned[ipOf(addr)]
	c.mu.Unlock()
	if ok {
		return k
	}
	return obfsKey{} // vide : le seal produit du bruit, jeté par le pair
}

func (c *WeChatPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.readMutex.Lock()
		n, addr, err := c.inner.ReadFrom(c.readBuf)
		if n <= wechatHeaderLen {
			c.readMutex.Unlock()
			if err != nil {
				return 0, addr, err
			}
			atomic.AddUint64(&obfsRxDropped, 1)
			continue
		}
		atomic.AddUint64(&obfsRxPackets, 1)
		body := c.readBuf[wechatHeaderLen:n]
		var data []byte
		if len(c.keys) == 1 {
			data = openObfs(c.keys[0], body)
		} else {
			for _, k := range obfsCandidateKeys() {
				if data = openObfs(k, body); data != nil {
					c.mu.Lock()
					if len(c.learned) >= 512 {
						c.learned = map[string]obfsKey{}
					}
					c.learned[ipOf(addr)] = k
					c.mu.Unlock()
					break
				}
			}
		}
		c.readMutex.Unlock()
		if data == nil {
			atomic.AddUint64(&obfsRxDropped, 1)
			if err != nil {
				return 0, addr, err
			}
			continue // bruit ou clé inconnue : jeté
		}
		atomic.AddUint64(&obfsRxOK, 1)
		return copy(p, data), addr, nil
	}
}

func (c *WeChatPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	key := c.sealFor(addr)
	atomic.AddUint64(&obfsTxPackets, 1)
	c.writeBuf[0] = 0xa1
	c.writeBuf[1] = 0x08
	binary.BigEndian.PutUint32(c.writeBuf[2:], c.sn)
	c.sn++
	c.writeBuf[6] = 0x00
	c.writeBuf[7] = 0x10
	c.writeBuf[8] = 0x11
	c.writeBuf[9] = 0x18
	c.writeBuf[10] = 0x30
	c.writeBuf[11] = 0x22
	c.writeBuf[12] = 0x30
	sealed := sealObfs(key, p)
	if sealed == nil {
		return 0, net.ErrClosed
	}
	if len(sealed) > len(c.writeBuf)-wechatHeaderLen {
		sealed = sealed[:len(c.writeBuf)-wechatHeaderLen]
	}
	copy(c.writeBuf[wechatHeaderLen:], sealed)
	_, err := c.inner.WriteTo(c.writeBuf[:wechatHeaderLen+len(sealed)], addr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *WeChatPacketConn) Close() error {
	return c.inner.Close()
}

func (c *WeChatPacketConn) LocalAddr() net.Addr {
	return c.inner.LocalAddr()
}

func (c *WeChatPacketConn) SetDeadline(t time.Time) error {
	return c.inner.SetDeadline(t)
}

func (c *WeChatPacketConn) SetReadDeadline(t time.Time) error {
	return c.inner.SetReadDeadline(t)
}

func (c *WeChatPacketConn) SetWriteDeadline(t time.Time) error {
	return c.inner.SetWriteDeadline(t)
}
