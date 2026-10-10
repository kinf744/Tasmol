package proto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"crypto/hmac"
	"crypto/sha256"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
	"io"
)

// SessionKeys dérivées du handshake (sens distincts C->S et S->C).
type SessionKeys struct {
	C2S [32]byte
	S2C [32]byte
}

// GenerateKeypair : paire X25519 éphémère.
func GenerateKeypair() (priv, pub [32]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return
	}
	buf, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, err
	}
	copy(pub[:], buf)
	return priv, pub, nil
}

// ServerDH / DH : exponentiation X25519.
func DH(priv *[32]byte, pub *[32]byte) ([32]byte, error)       { return dh(priv, pub) }
func ServerDH(priv *[32]byte, pub *[32]byte) ([32]byte, error) { return dh(priv, pub) }

// DeriveKeys : version exportée de deriveKeys.
func DeriveKeys(shared *[32]byte, psk []byte) *SessionKeys { return deriveKeys(shared, psk) }

// HandshakeConfirm : AEAD(∅) avec clé C2S, nonce nulle, AAD=ephClient — 16 octets.
func HandshakeConfirm(c2s *[32]byte, ephClient *[32]byte) []byte {
	nonce := make([]byte, nonceLen)
	return aeadSeal(c2s, nonce, nil, ephClient[:])[:16]
}

func dh(priv *[32]byte, pub *[32]byte) ([32]byte, error) {
	var out [32]byte
	buf, err := curve25519.X25519(priv[:], pub[:])
	copy(out[:], buf)
	return out, err
}

// deriveKeys : HKDF-SHA3 sur le secret DH, informé par le PSK du service.
func deriveKeys(shared *[32]byte, psk []byte) *SessionKeys {
	h := hkdf.New(sha3.New256, shared[:], psk, []byte("utunnel/v1 session"))
	sk := &SessionKeys{}
	io.ReadFull(h, sk.C2S[:])
	io.ReadFull(h, sk.S2C[:])
	return sk
}

// handshakeMAC : HMAC-SHA256(psk, ephPub | ts) pour authentifier handshake1.
func handshakeMAC(psk, ephPub []byte, ts int64) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write(ephPub)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	m.Write(b[:])
	return m.Sum(nil)[:16]
}

// BuildHandshake1 construit le message d'ouverture client.
func BuildHandshake1(psk []byte, ephPub *[32]byte, ts int64) []byte {
	out := make([]byte, 0, PreKeyLen)
	out = append(out, ephPub[:]...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	out = append(out, b[:]...)
	out = append(out, handshakeMAC(psk, ephPub[:], ts)...)
	return out
}

// ParseHandshake1 vérifie l'authenticité et la fraîcheur (±120 s).
func ParseHandshake1(psk, raw []byte, now int64) (ephPub [32]byte, err error) {
	if len(raw) < PreKeyLen {
		err = ErrBadPacket
		return
	}
	copy(ephPub[:], raw[:32])
	ts := int64(binary.BigEndian.Uint64(raw[32:40]))
	diff := now - ts
	if diff < -120 || diff > 120 {
		err = ErrSessExpired
		return
	}
	expect := handshakeMAC(psk, ephPub[:], ts)
	if !hmac.Equal(expect, raw[40:56]) {
		err = ErrBadAuth
		return
	}
	// padding QUIC (RFC 9000 §14.1) : le handshake1 est paddé à 1300 B
	// (1200+ MINIMUM — les opérateurs traitent ces tailles comme du
	// trafic légitime). Le padding aléatoire n'est jamais lu.
	if len(raw) > PreKeyLen+1400 {
		err = ErrBadPacket
		return
	}
	return
}

// BuildHandshake2 : réponse serveur = ephPub || confirm16.
func BuildHandshake2(ephPub *[32]byte, confirm []byte) []byte {
	out := make([]byte, 0, 48)
	out = append(out, ephPub[:]...)
	out = append(out, confirm[:16]...)
	return out
}

func aeadSeal(key *[32]byte, nonce, plain, aad []byte) []byte {
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	return a.Seal(nil, nonce, plain, aad)
}

func aeadOpen(key *[32]byte, nonce, ct, aad []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, ct, aad)
}

var _ = errors.New
