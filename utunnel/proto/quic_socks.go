package proto

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

// ── Transport QUIC du tunnel utunnel (quic-go) ─────────────────────────
//
// POURQUOI QUIC : le CGNAT/DPI d'Orange bloque chaque flux UDP custom
// après 1-2 paquets (détecté par le DPI — le padding, les hops, les
// retransmissions, le mimic 0x40 n'y changent rien : 715 paquets serveur
// envoyés, aucun reçu, rtt=0ms permanent). QUIC est indistinguable du
// trafic HTTPS/3 légitime — le DPI le WHITELISTE (le zivpn/Hysteria
// pousse 18 Mo+ sur le même réseau).
//
// DÉPENDANCE : quic-go est une BIBLIOTHÈQUE Go compilée DANS notre
// binaire (lib_utunnel.so) — pas un binaire externe. L'identité utunnel
// est PRÉSERVÉE : l'auth PSK (SHA256(uuid:secret) servie par l'API
// stivaros), la plage de ports (50000-59999 DNAT-ée), le port hopping
// (la re-dial adaptative), les streams TCP/UDP.
//
// TLS : le handshake standard 1.3 avec le cert auto-signé du serveur
// (le client insecure) — indistinguable d'un handshake HTTPS/3. L'AUTH
// UTUNNEL : le premier stream : [2B len][PSK] vérifié par le serveur
// (le PSK = SHA256(uuid:secret) — la même formule stivaros).
//
// ── Protocole par-dessus QUIC ──────────────────────────────────────────
//   - Stream bidirectionnel par CONNECT : [2B len][addr][status 1B] puis
//     le bridge bidirectionnel (le TCP target) ;
//   - Datagrammes QUIC pour l'UDP : [2B len][dst][payload] ;
//   - Le keepalive QUIC natif (KeepAlivePeriod) — indistinguable.

// UTUNNEL_ALPN : l'ALPN du tunnel (notre protocole, version 1).
const UTUNNEL_ALPN = "utunnel/1"

// UTUNNEL_DIAL_TIMEOUT : le délai d'établissement QUIC.
const UTUNNEL_DIAL_TIMEOUT = 15 * time.Second

// tlsCfgQUIC : le config TLS — le cert auto-signé du serveur (le client
// : insecure). Indistinguable d'un handshake HTTPS/3 pour le DPI.
func tlsCfgQUIC(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return &tls.Config{
			NextProtos:         []string{UTUNNEL_ALPN},
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		}, nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{UTUNNEL_ALPN},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// clientTLSCfg : le client : insecure (le cert auto-signé du serveur).
func clientTLSCfg() *tls.Config {
	return &tls.Config{
		NextProtos:         []string{UTUNNEL_ALPN},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // le cert auto-signé stivaros
	}
}

// ParsePortRange : "50000-59999" ou "50000" → (min, max).
func ParsePortRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '-'); i > 0 {
		lo, err := strconv.Atoi(strings.TrimSpace(s[:i]))
		if err != nil {
			return 0, 0, err
		}
		hi, err := strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if err != nil {
			return 0, 0, err
		}
		return lo, hi, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, err
	}
	return v, v, nil
}

// ResolveInitialAddrQUIC : "IP:plage" → le port initial ALÉATOIRE de la
// plage (la spec Hysteria : le premier port aléatoire, les hops ensuite).
func ResolveInitialAddrQUIC(addr string) string {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if !strings.ContainsAny(portStr, "-,") {
		return addr
	}
	lo, hi, perr := ParsePortRange(portStr)
	if perr != nil || hi < lo {
		return addr
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	port := lo + int(b[0])%(hi-lo+1)
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// DialQUIC : le client QUIC — la connexion vers le serveur utunnel.
// addr : "IP:port" ou "IP:plage" (le port initial aléatoire).
func DialQUIC(ctx context.Context, addr string) (quic.Connection, error) {
	addr = ResolveInitialAddrQUIC(addr)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, UTUNNEL_DIAL_TIMEOUT)
	defer cancel()
	quicCfg := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 5 * time.Second, // le ping QUIC natif (indistinguable)
	}
	qconn, err := quic.DialEarly(dctx, udpConn, udpAddr, clientTLSCfg(), quicCfg)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("quic dial: %w", err)
	}
	return qconn, nil
}

// ListenQUIC : le serveur QUIC — écoute :port (le DNAT plage → ce port).
func ListenQUIC(addr, certFile, keyFile string) (*quic.EarlyListener, error) {
	tlsCfg, err := tlsCfgQUIC(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	quicCfg := &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	}
	return quic.ListenAddrEarly(addr, tlsCfg, quicCfg)
}

// AcceptQUIC : accepte une connexion cliente.
func AcceptQUIC(ctx context.Context, l *quic.EarlyListener) (quic.Connection, error) {
	return l.Accept(ctx)
}

// AuthStream : le premier stream = L'AUTH UTUNNEL : [2B len][PSK] — le
// serveur vérifie le PSK (SHA256(uuid:secret)) sinon ferme.
// Le PSK correct → le stream reste ouvert (le canal de données).
func AuthStream(q quic.Connection, psk string, timeout time.Duration) (quic.Stream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	st, err := q.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	var hdr [2]byte
	hdr[0] = byte(len(psk) >> 8)
	hdr[1] = byte(len(psk))
	if _, err := st.Write(append(hdr[:], []byte(psk)...)); err != nil {
		st.Close()
		return nil, err
	}
	var ack [1]byte
	if _, err := io.ReadFull(st, ack[:]); err != nil {
		st.Close()
		return nil, fmt.Errorf("auth: %w", err)
	}
	if ack[0] != 1 {
		st.Close()
		return nil, fmt.Errorf("auth: refusée par le serveur")
	}
	return st, nil
}

// AcceptAuthStream : le serveur : lit et vérifie le PSK du premier stream.
// OK → le stream est retourné (le canal de données). KO → fermé.
func AcceptAuthStream(q quic.Connection, valid func(string) bool, timeout time.Duration) (quic.Stream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	st, err := q.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(st, hdr[:]); err != nil {
		st.Close()
		return nil, err
	}
	l := int(hdr[0])<<8 | int(hdr[1])
	if l > 256 {
		st.Close()
		return nil, fmt.Errorf("auth: longueur invalide")
	}
	psk := make([]byte, l)
	if _, err := io.ReadFull(st, psk); err != nil {
		st.Close()
		return nil, err
	}
	if !valid(string(psk)) {
		st.Close()
		return nil, fmt.Errorf("auth: PSK inconnue")
	}
	if _, err := st.Write([]byte{1}); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

// QUICBridge : le pont bidirectionnel QUIC stream ↔ conn (net.Conn).
func QUICBridge(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(b, a); cwb(b); done <- struct{}{} }()
	go func() { io.Copy(a, b); cwa(a); done <- struct{}{} }()
	<-done
}

// cwa/cwb : les half-closes (le QUIC stream et le TCP le supportent).
func cwa(a io.ReadWriteCloser) {
	if s, ok := a.(quic.Stream); ok {
		s.Close()
	}
}
func cwb(b io.ReadWriteCloser) {
	if c, ok := b.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
	} else if s, ok := b.(quic.Stream); ok {
		s.Close()
	}
}

// serveCert : génère un cert auto-signé si absent (le serveur).
func serveCert(certPath, keyPath, domain string) error {
	if certExists(certPath, keyPath) {
		return nil
	}
	priv, err := rsaGen()
	if err != nil {
		return err
	}
	tmpl := x509Template(domain)
	der, err := x509Create(tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	return x509Write(certPath, keyPath, der, priv)
}

// rsaGen : une clé RSA 2048 (le cert auto-signé).
func rsaGen() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// x509Template : le template du cert auto-signé.
func x509Template(domain string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"Stivaros"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}
}

// x509Create : auto-signé (le template = le parent).
func x509Create(tmpl, parent *x509.Certificate, pub, priv interface{}) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
}

// x509Write : écrit cert.pem/key.pem.
func x509Write(certPath, keyPath string, der []byte, priv *rsa.PrivateKey) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0600)
}

// certExists : les deux fichiers présents.
func certExists(certPath, keyPath string) bool {
	if _, err := os.Stat(certPath); err != nil {
		return false
	}
	_, err := os.Stat(keyPath)
	return err == nil
}

// LoadPSKFromString : la PSK depuis une string (64 hex → les octets ;
// sinon le brut — le serveur : auth.config inclut les deux formats).
func LoadPSKFromString(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		out := make([]byte, 32)
		for i := 0; i < 32; i++ {
			v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
			if err != nil {
				return nil, err
			}
			out[i] = byte(v)
		}
		return out, nil
	}
	sum := sha256.Sum256([]byte(s))
	return sum[:], nil
}

// UDPAssociateOverQUIC : le relais UDP (le DNS) via les datagrammes
// QUIC : [2B len][dst][payload] — le serveur : sendto + la réponse.
func UDPAssociateOverQUIC(q quic.Connection, socks net.Conn) {
	defer socks.Close()
	// Le datagramme du téléphone : dst + payload → le serveur.
	done := make(chan struct{})
	go func() {
		defer close(done)
		var hdr [2]byte
		for {
			if _, err := io.ReadFull(socks, hdr[:]); err != nil {
				return
			}
			l := int(hdr[0])<<8 | int(hdr[1])
			if l > 2048 {
				return
			}
			pkt := make([]byte, l)
			if _, err := io.ReadFull(socks, pkt); err != nil {
				return
			}
			if len(pkt) < 7 {
				return
			}
			// [atyp][addr][port][payload] (le format SOCKS5 UDP)
			var dst *net.UDPAddr
			var payload []byte
			switch pkt[3] {
			case 1:
				dst = &net.UDPAddr{IP: net.IPv4(pkt[4], pkt[5], pkt[6], pkt[7]),
					Port: int(binary.BigEndian.Uint16(pkt[8:]))}
				payload = pkt[10:]
			case 3:
				dl := int(pkt[4])
				host := string(pkt[5 : 5+dl])
				port := int(binary.BigEndian.Uint16(pkt[5+dl:]))
				ips, err := net.LookupIP(host)
				if err != nil {
					continue
				}
				dst = &net.UDPAddr{IP: ips[0], Port: port}
				payload = pkt[7+dl:]
			default:
				continue
			}
			conn, err := net.DialUDP("udp", nil, dst)
			if err != nil {
				continue
			}
			conn.Write(payload)
			conn.Close()
		}
	}()
	// Les réponses du serveur : [2B len][dst][payload] → le SOCKS.
	for {
		dg, err := q.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if len(dg) < 3 {
			continue
		}
		var hdr [2]byte
		hdr[0] = byte(len(dg) >> 8)
		hdr[1] = byte(len(dg))
		socks.Write(append(hdr[:], dg...))
	}
}
