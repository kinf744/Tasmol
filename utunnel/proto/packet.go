// Package proto implémente le cœur du tunnel utunnel :
// fiabilisation sélective sur UDP, multiplexage de flux et chiffrement
// session X25519 + ChaCha20-Poly1305 avec obfuscation d'en-tête.
package proto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// ── Format du paquet chiffré sur le fil ─────────────────────────────────
//
//   [8B  token]   identifiant de session (AAD), obfusqué par XOR-rolling
//   [12B nonce]   aléatoire unique par paquet
//   [ciphertext]  AEAD( header:16B | payload )
//
// header clair (16B) :
//   [1B type][1B flags][2B window][4B seq][4B ack][4B ackBits]
//
// Le token sert aussi de masque : avant envoi, on XOR token+nonce avec un
// flux dérivé de la clé de session (obfuscation statistique d'en-tête).
// Aucun littéral magique constant n'apparaît sur le fil.

const (
	TypeHandshake1 = 0x01 // client -> serveur : [32B eph x25519][8B ts][16B hmac]
	TypeHandshake2 = 0x02 // serveur -> client : [32B eph x25519][16B confirm]
	TypeData       = 0x10 // payload : frames mux fiables
	TypePureAck    = 0x11 // ack sans données
	TypeUDPData    = 0x12 // payload datagramme (non fiable, chiffré)
	TypeCloseSess  = 0x1f
)

const (
	hdrLen     = 16
	tokenLen   = 8
	nonceLen   = 24 // XChaCha20-Poly1305 : nonce 24B aléatoire par paquet
	aeadOver   = 16
	MinPktLen  = tokenLen + nonceLen + aeadOver + hdrLen
	PreKeyLen  = 56 // taille handshake1 (32B eph + 8B ts + 16B mac)
	MTUDefault = 1232
)

var (
	ErrBadPacket   = errors.New("paquet invalide")
	ErrDecrypt     = errors.New("déchiffrement impossible")
	ErrReplay      = errors.New("paquet rejeté (anti-rejeu)")
	ErrBadAuth     = errors.New("authentification refusée")
	ErrSessExpired = errors.New("session expirée")
)

// encodePacket chiffre et obfusque un paquet sortant.
// flags/window sont injectés dans l'en-tête ; seq/ack/ackBits par la session.
func encodePacket(key *[32]byte, token *[tokenLen]byte, typ uint8, flags uint8, window uint16, seq, ack, ackBits uint32, payload []byte) []byte {
	var hdr [hdrLen]byte
	hdr[0] = typ
	hdr[1] = flags
	binary.BigEndian.PutUint16(hdr[2:], window)
	binary.BigEndian.PutUint32(hdr[4:], seq)
	binary.BigEndian.PutUint32(hdr[8:], ack)
	binary.BigEndian.PutUint32(hdr[12:], ackBits)

	mask := headerMask(key)
	// QUIC MIMIC : wire[0] = 0x40 (le flag des en-têtes courts QUIC) —
	// le token effectif[0] = 0x40^mask[0], utilisé pour l'AAD ET le wire
	// (cohérence encode/décode garantie).
	tokEff := *token
	tokEff[0] = 0x40 ^ mask[0]

	var nonce [nonceLen]byte
	rand.Read(nonce[:])

	plain := make([]byte, 0, hdrLen+len(payload))
	plain = append(plain, hdr[:]...)
	plain = append(plain, payload...)

	inner := aeadSeal(key, nonce[:], plain, tokEff[:])
	out := make([]byte, 0, tokenLen+nonceLen+len(inner))
	out = append(out, 0x40) // QUIC short-header flag (forcé)
	for i := 1; i < tokenLen; i++ {
		out = append(out, tokEff[i]^mask[i])
	}
	out = append(out, nonce[:]...)
	out = append(out, inner...)
	return out
}

// decodePacket retire l'obfuscation, déchiffre et retourne l'en-tête + payload.
func decodePacket(key *[32]byte, raw []byte) (typ, flags uint8, window uint16, seq, ack, ackBits uint32, payload []byte, err error) {
	if len(raw) < MinPktLen {
		err = ErrBadPacket
		return
	}
	var token [tokenLen]byte
	mask := headerMask(key)
	// QUIC MIMIC : wire[0] = 0x40 forcé (le flag QUIC) → token[0] =
	// 0x40^mask[0] (la même valeur effective des deux côtés — l'AAD
	// construit dans encodePacket avec tokEff[0] = 0x40^mask[0]).
	token[0] = 0x40 ^ mask[0]
	for i := 1; i < tokenLen; i++ {
		token[i] = raw[i] ^ mask[i]
	}
	nonce := raw[tokenLen : tokenLen+nonceLen]
	plain, derr := aeadOpen(key, nonce, raw[tokenLen+nonceLen:], token[:])
	if derr != nil {
		err = ErrDecrypt
		return
	}
	if len(plain) < hdrLen {
		err = ErrBadPacket
		return
	}
	typ, flags = plain[0], plain[1]
	window = binary.BigEndian.Uint16(plain[2:])
	seq = binary.BigEndian.Uint32(plain[4:])
	ack = binary.BigEndian.Uint32(plain[8:])
	ackBits = binary.BigEndian.Uint32(plain[12:])
	payload = plain[hdrLen:]
	return
}

// headerMask : 8 octets de masque dérivés de la clé (XOR-rolling simple).
func headerMask(key *[32]byte) [tokenLen]byte {
	var m [tokenLen]byte
	k := key[:]
	m[0] = k[0] ^ k[7] ^ k[15] ^ k[23]
	m[1] = k[1] ^ k[9] ^ k[17] ^ k[25]
	m[2] = k[2] ^ k[11] ^ k[19] ^ k[27]
	m[3] = k[3] ^ k[13] ^ k[21] ^ k[29]
	m[4] = k[4] ^ k[8] ^ k[16] ^ k[31]
	m[5] = k[5] ^ k[10] ^ k[18] ^ k[26]
	m[6] = k[6] ^ k[12] ^ k[20] ^ k[28]
	m[7] = k[7] ^ k[14] ^ k[22] ^ k[30]
	return m
}
