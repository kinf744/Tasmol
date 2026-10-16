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
	"sync"

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

// ResolveInitialAddrQUIC : "IP:port,plage,…" → le port CANDIDAT n°attempt.
// La liste permet au client de contourner un port que l'opérateur filtre :
// "443,50000-59999" essaie le 443 (HTTPS/3 légitime), puis un port
// aléatoire de la plage, puis recommence — l'ordre tourne à chaque essai.
func ResolveInitialAddrQUIC(addr string, attempt int) string {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	var cands []string
	for _, part := range strings.Split(portStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, perr := ParsePortRange(part); perr == nil && hi >= lo {
			if hi > lo {
				var b [2]byte
				_, _ = rand.Read(b[:])
				part = strconv.Itoa(lo + int(b[0])%(hi-lo+1))
			}
			cands = append(cands, part)
		}
	}
	if len(cands) == 0 {
		return addr
	}
	return net.JoinHostPort(host, cands[attempt%len(cands)])
}

// CandidateAddrs : décompose "ip:c1,c2-c3,…" en UN addr aléatoire PAR
// classe (le random plein-frange — 15000 + rand%1000 pour 15000-15999,
// pas le b[0] 0-255 qui ne couvrait que les 256 premiers ports).
func CandidateAddrs(addr string) []net.Addr {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	var addrs []net.Addr
	for _, part := range strings.Split(portStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, perr := ParsePortRange(part)
		if perr != nil || hi < lo {
			continue
		}
		var port int
		if hi > lo {
			var b [2]byte
			_, _ = rand.Read(b[:])
			port = lo + int(binary.BigEndian.Uint16(b[:]))%(hi-lo+1)
		} else {
			port = lo
		}
		addrs = append(addrs, &net.UDPAddr{IP: net.ParseIP(host), Port: port})
	}
	return addrs
}

// NewClientPacketConn : un socket local frais, obfusqué, pointant la
// destination candidate n°attempt. Utilisé seul (une tentative) ou via
// HopPacketConn (la rotation continue à la Hysteria).
func NewClientPacketConn(addr, pskHex string, attempt int) (net.PacketConn, string, error) {
	sAddr := ResolveInitialAddrQUIC(addr, attempt)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, "", err
	}
	if pskHex != "" {
		return NewClientObfsConn(udpConn, deriveObfsKey(pskHex)), sAddr, nil
	}
	return udpConn, sAddr, nil
}

// DialQUIC : le client QUIC — la connexion vers le serveur utunnel.
// addr : "IP:port" ou "IP:plage" (le port initial aléatoire).
// pskHex : la PSK (64-hex) — dérive aussi la clé d'obfuscation UDP
// (anti-DPI/CGNAT : les paquets ressortent paddés et indistinguables).
func DialQUIC(ctx context.Context, addr, pskHex string, attempt int) (quic.Connection, error) {
	pc, sAddr, err := NewClientPacketConn(addr, pskHex, attempt)
	if err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", sAddr)
	if err != nil {
		pc.Close()
		return nil, err
	}
	quicCfg := &quic.Config{
		EnableDatagrams:      true, // le relais UDP (les datagrammes QUIC)
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      5 * time.Second, // le ping QUIC natif (indistinguable)
		HandshakeIdleTimeout: 4 * time.Second,
		// DisablePathMTUDiscovery : les sondes DPLPMTUD (paquets surdimensionnés)
		// peuvent déclencher les filtres des CGNAT — on reste à 1252 B.
		DisablePathMTUDiscovery: true,
	}
	// Transport EXPLICITE : quic.DialEarly(ctx, pc, ...) passe par le
	// multiplexeur GLOBAL de quic-go (clé = LocalAddr) — avec nos
	// HopPacketConn en rotation et les vagues de chasse qui se
	// chevauchent, deux enregistrements entraînaient
	// « panic: connection already exists » qui tuait tout le client.
	// Un Transport dédié par connexion contourne le multiplexeur.
	tr := &quic.Transport{Conn: pc}
	// NOTE : PAS de cancel() après le dial — DialEarly lie la connexion
	// au contexte : l'annuler avant la confirmation du handshake TUERAIT
	// la connexion (le bug qui bloquait la chasse en silence).
	qconn, err := tr.DialEarly(ctx, udpAddr, clientTLSCfg(), quicCfg)
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("quic dial: %w", err)
	}
	return qconn, nil
}

// DialQUICWithPC : le dial QUIC sur un PacketConn FOURNI (le hop conn
// en rotation à la Hysteria) — la connexion migre quand le hop tourne.
func DialQUICWithPC(ctx context.Context, pc net.PacketConn, sAddr, pskHex string) (quic.Connection, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", sAddr)
	if err != nil {
		pc.Close()
		return nil, err
	}
	quicCfg := &quic.Config{
		EnableDatagrams: true, // le relais UDP (les datagrammes QUIC)
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 5 * time.Second, // le ping QUIC natif (indistinguable)
		// DisablePathMTUDiscovery : les sondes DPLPMTUD (paquets surdimensionnés)
		// peuvent déclencher les filtres des CGNAT — on reste à 1252 B.
		DisablePathMTUDiscovery: true,
	}
	// NOTE : PAS de cancel() après le dial — DialEarly lie la connexion
	// au contexte : l'annuler avant la confirmation du handshake TUERAIT
	// la connexion (le bug qui bloquait la chasse en silence).
	qconn, err := quic.DialEarly(ctx, pc, udpAddr, clientTLSCfg(), quicCfg)
	if err != nil {
		pc.Close()
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
		EnableDatagrams: true, // le relais UDP (les datagrammes QUIC)
		MaxIdleTimeout:  30 * time.Second,
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
	// CRITIQUE : le read de l'ack N'HÉRITE d'aucun deadline — sur un
	// chemin mort il bloque À L'INFINI (le timeout ne couvrait que
	// OpenStreamSync) et le client n'hoppe jamais vers un autre port.
	_ = st.SetWriteDeadline(time.Now().Add(timeout))
	_ = st.SetReadDeadline(time.Now().Add(timeout))
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
// UDPAssociateOverQUIC : le SOCKS5 UDP ASSOCIATE standard. L'app (gVisor
// tun2socks) ouvre une socket UDP vers 127.0.0.1:<port BND> et parle le
// datagramme SOCKS5 [RSV 2B][FRAG 1B][ATYP][addr][port][payload]. Le
// client strip le préfixe SOCKS et envoie [2B len][ATYP][addr][port]
// [payload] en datagramme QUIC ; les réponses du serveur suivent le
// chemin inverse. up paces l'uplink en mode brutal (nil = pas de pacing).
func UDPAssociateOverQUIC(q quic.Connection, socks net.Conn, up *Pacer) {
	defer socks.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// La socket UDP de relais locale (le BND annoncé à l'app).
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer udp.Close()
	lport := udp.LocalAddr().(*net.UDPAddr).Port
	resp := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(lport >> 8), byte(lport)}
	if _, err := socks.Write(resp); err != nil {
		return
	}
	var appMu sync.Mutex
	var appAddr *net.UDPAddr
	// La fermeture du contrôle TCP = la fin de l'association.
	go func() {
		io.Copy(io.Discard, socks)
		cancel()
	}()
	// Les requêtes de l'app → les datagrammes QUIC (l'uplink).
	go func() {
		buf := make([]byte, 65536)
		for {
			n, src, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 4+3 || buf[2] != 0 { // RSV 2B + FRAG 1B + ATYP/addr/port
				continue // FRAG≠0 (réassemblage) non supporté, comme la plupart des proxies
			}
			appMu.Lock()
			appAddr = src
			appMu.Unlock()
			inner := buf[3:n] // [ATYP][addr][port][payload]
			if len(inner) > 1198 {
				continue // le datagramme QUIC tient dans le PMTU
			}
			if up != nil {
				up.Wait(len(inner) + 2)
			}
			var hdr [2]byte
			hdr[0] = byte(len(inner) >> 8)
			hdr[1] = byte(len(inner))
			out := make([]byte, 0, len(inner)+2)
			out = append(out, hdr[0], hdr[1])
			out = append(out, inner...)
			if err := q.SendDatagram(out); err != nil {
				return
			}
		}
	}()
	// Les réponses du serveur → l'app (ré-encapsulées en SOCKS5 UDP).
	for {
		dg, err := q.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(dg) < 4 {
			continue
		}
		l := int(dg[0])<<8 | int(dg[1])
		if l+2 > len(dg) {
			continue
		}
		inner := dg[2 : 2+l]
		appMu.Lock()
		dst := appAddr
		appMu.Unlock()
		if dst == nil {
			continue
		}
		out := make([]byte, 0, len(inner)+3)
		out = append(out, 0, 0, 0) // RSV 0, FRAG 0
		out = append(out, inner...)
		udp.WriteToUDP(out, dst)
	}
}
