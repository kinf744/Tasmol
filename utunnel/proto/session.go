package proto

import (
	"container/heap"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ── Session fiable sur UDP ───────────────────────────────────────────────
//
// Congestion / fiabilité (inspiré KCP + LEDBAT, sans Hysteria ni QUIC) :
//   - fenêtre d'émission glissante (snd_wnd) avec ACK sélectif par bitmask ;
//   - retransmission rapide après 3 ACK dupliqués ou expiration RTO ;
//   - RTO adaptatif Jacobson/Karels (min 100 ms) ;
//   - contrôle de congestion AIMD doux + slow-start (cwnd) ;
//   - pacing : émissions espacées de cwnd/srtt pour lisser la rafale ;
// keepalive : fréquence AGRESSIVE (1 s) — sur les réseaux mobiles où
// le CGNAT ne maintient le mapping que brièvement (un nouveau mapping
// par paquet sortant), seuls les échanges IMMÉDIATS passent de façon
// fiable (capture tcpdump : ~95% des paquets "spontanés" perdus, les
// ping/pong fiables). Chaque ping déclenche côté serveur la
// retransmission immédiate de l'en vol (forceRetransmit) + le pong —
// les données sont récupérées en continu. Coût : ~60 B/s, négligeable.
//
// La session émet des *frames de stream* fiables (cf. mux.go) et des
// datagrammes TypeUDPData non fiables (relais UDP brut).

const (
	sessWindow  = 512  // tailles fenêtre & reused (paquet seq space)
	sndBufCap   = 1024 // segments en vol max
	rcvWindow   = 1024
	keepalive   = 1 * time.Second
	sessTimeout = 30 * time.Second
	minRTO      = 80 * time.Millisecond
	initRTO     = 300 * time.Millisecond
	maxMTU      = 1400
	defaultCWND = 32
	maxCWND     = 4096
)

var (
	ErrSessionClosed = errors.New("session fermée")
	ErrStreamClosed  = errors.New("stream fermé")
)

// Session côté canal fiable métrique.
type Session struct {
	conn   *net.UDPConn
	remote *net.UDPAddr // dernier pair vu (port hopping)
	key    *[32]byte
	txKey  [32]byte
	rxKey  [32]byte
	token  [tokenLen]byte

	mu           sync.Mutex
	isServer     bool
	dead         bool
	die          chan struct{}
	closed       chan struct{}      // fermé quand mort
	onPairChange func(*net.UDPAddr) // purge conntrack de l'ancien pair (hop-dst)

	// trafic : octets de données (payload mux) par sens. Diagnostics
	// "downlink calé à 0B" : le log périodique du serveur et du client
	// montre si le trafic passe réellement dans chaque direction.
	bytesIn  atomic.Int64 // payload reçu du pair (client: downlink)
	bytesOut atomic.Int64 // payload envoyé au pair (client: uplink)
	pktsIn   atomic.Int64 // paquets décodés OK (tout type) — vie de la session
	pktsBad  atomic.Int64 // paquets indéchiffrables (PSK, tamper, troncature)
	retrs    atomic.Int64 // retransmissions émises (les pertes du réseau)
	lastPing atomic.Int64 // unix-nanos du dernier ping envoyé (0 = jamais)
	lastRTT  atomic.Int64 // RTT du dernier ping/pong (ms ; 0 = jamais)

	// émission
	txSeq    uint32
	unacked  map[uint32]*seg
	unackedQ segHeap
	sndWnd   int
	cwnd     float64
	pacing   time.Duration
	lastPace time.Time

	// réception
	rxBase   uint32 // plus petit seq attendu (cumulatif)
	rxSeen   map[uint32]bool
	fastRetr map[uint32]int
	ackPend  bool // données reçues à acquitter au prochain flush

	// RTT estimés (Jacobson)
	srtt   float64 // µs
	rttvar float64

	// streams mux
	mux *Mux

	// callbacks datagramme non fiable
	onUDPPacket func(payload []byte)

	lastRX   time.Time
	lastTX   time.Time
	inflight int // segments ÉMIS et non acquittés (pas seulement en file)
}

var errTimeout = errors.New("timeout")

type seg struct {
	seq    uint32
	typ    uint8
	data   []byte
	sentAt time.Time
	xmit   int
}

type segHeap []*seg

func (h segHeap) Len() int           { return len(h) }
func (h segHeap) Less(i, j int) bool { return h[i].seqBefore(h[j]) }
func (s *seg) seqBefore(o *seg) bool { return int32(s.seq-o.seq) < 0 }
func (h segHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *segHeap) Push(x any)        { *h = append(*h, x.(*seg)) }
func (h *segHeap) Pop() any {
	old := *h
	n := len(old)
	s := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return s
}

// Handshake1 réémis tant que handshake2 n'arrive pas : un seul envoi +
// pertes réelles du lien (15 % bidirectionnel ≈ 28 % d'échec par tentative)
// rendaient le handshake non fiable. Le MÊME h1 (même ephémère) est réémis :
// le serveur déduplique par ephémère et retransmet le même handshake2.
const (
	hsAttempts  = 8
	hsRetryWait = 2 * time.Second
)

// NewSession (client): démarre le handshake.
func NewSession(conn *net.UDPConn, remote *net.UDPAddr, psk []byte, isServer bool) (*Session, error) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	h1raw := BuildHandshake1(psk, &pub, time.Now().Unix())
	// PADDING QUIC (RFC 9000 §14.1) : 1200+ octets MINIMUM — les
	// opérateurs traitent ces tailles comme du trafic légitime (le
	// zivpn/QUIC passe, nos petits paquets 56 B étaient bloqués comme du
	// flood). Le parseur handshake ignore le trailing garbage.
	pad := make([]byte, 1300)
	rand.Read(pad)
	h1 := append(h1raw, pad...)

	buf := make([]byte, 2048)
	var n int
	for attempt := 0; attempt < hsAttempts; attempt++ {
		if _, err := conn.WriteToUDP(h1, remote); err != nil {
			return nil, err
		}
		conn.SetReadDeadline(time.Now().Add(hsRetryWait))
		var rerr error
		n, _, rerr = conn.ReadFromUDP(buf)
		if rerr == nil {
			break
		}
		if ne, ok := rerr.(net.Error); !ok || !ne.Timeout() {
			conn.SetReadDeadline(time.Time{})
			return nil, rerr
		}
		n = 0
	}
	conn.SetReadDeadline(time.Time{})
	if n == 0 {
		return nil, errTimeout
	}
	if n < 48 {
		return nil, ErrBadPacket
	}
	var serverPub [32]byte
	copy(serverPub[:], buf[:32])
	confirm := buf[32:48]

	shared, err := dh(&priv, &serverPub)
	if err != nil {
		return nil, err
	}
	keys := deriveKeys(&shared, psk)
	m := HandshakeConfirm(&keys.C2S, &pub)
	if !equalCt(m, confirm) {
		return nil, ErrBadAuth
	}
	s := mkSession(conn, remote, keys, false)
	_ = isServer
	go s.reader()
	return s, nil
}

// NewServerSession construit la session côté serveur après handshake1 validé.
// tokenWire = les 8 premiers octets BRUTS vus sur le fil (masqués) — la
// démux du serveur indexe dessus, avant tout déchiffrement.
func NewServerSession(conn *net.UDPConn, remote *net.UDPAddr, keys *SessionKeys) *Session {
	return mkSession(conn, remote, keys, true)
}

// WireToken retourne les 8 octets d'en-tête tels qu'ils apparaissent sur le
// fil pour les paquets émis vers cette session (sens pair->nous).
func (s *Session) WireToken() [tokenLen]byte {
	mask := headerMask(&s.rxKey)
	var w [tokenLen]byte
	for i := 0; i < tokenLen; i++ {
		w[i] = s.rxKey[i] ^ mask[i]
	}
	w[0] = 0x40 // QUIC MIMIC : le flag forcé (cohérent avec encodePacket)
	return w
}

// Stats retourne les octets de trafic par sens (payload fiable + UDP) :
// (rxBytes, txBytes). Côté client, rxBytes = downlink (réponses du serveur),
// txBytes = uplink (données envoyées). Diagnostics "downlink calé à 0B" :
// le log périodique du serveur et du client montre la direction morte.
func (s *Session) Stats() (int64, int64) {
	return s.bytesIn.Load(), s.bytesOut.Load()
}

// SessionStats : l'état complet du chemin — diagnostics kighmu.txt.
type SessionStats struct {
	RxBytes  int64  // payload reçu (client: downlink)
	TxBytes  int64  // payload envoyé (client: uplink)
	PktsIn   int64  // paquets décodés OK
	PktsBad  int64  // paquets indéchiffrables
	Retrans  int64  // retransmissions émises (les pertes réseau)
	Inflight int    // segments en vol non acquittés
	RTTms    int64  // latence du dernier ping/pong (0 = jamais mesurée)
	Remote   string // dernier pair vu (le port externe CGNAT)
}

// FullStats retourne l'état complet du chemin pour le diagnostic.
func (s *Session) FullStats() SessionStats {
	s.mu.Lock()
	infl := s.inflight
	rem := "?"
	if s.remote != nil {
		rem = s.remote.String()
	}
	s.mu.Unlock()
	rx, tx := s.Stats()
	in, bad := s.PacketStats()
	return SessionStats{
		RxBytes:  rx,
		TxBytes:  tx,
		PktsIn:   in,
		PktsBad:  bad,
		Retrans:  s.retrs.Load(),
		Inflight: infl,
		RTTms:    s.lastRTT.Load(),
		Remote:   rem,
	}
}

// PacketStats retourne (pktsIn, pktsBad) : paquets décodés OK vs
// indéchiffrables. pktsBad>0 avec rx=0 = PSK invalide ou troncature —
// diagnostics dans kighmu.txt.
func (s *Session) PacketStats() (int64, int64) {
	return s.pktsIn.Load(), s.pktsBad.Load()
}

// Dead retourne vrai si la session est morte (usage surveillance client).
func (s *Session) Dead() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dead
}

// SetPairChangeHandler enregistre le callback appelé quand le pair change
// (le serveur suit le port-hopping destination de l'app). Le serveur purge
// l'ancienne entrée conntrack pour éliminer l'ambiguïté du retour.
func (s *Session) SetPairChangeHandler(fn func(*net.UDPAddr)) {
	s.onPairChange = fn
}

// RemoteString retourne le dernier pair vu (thread-safe), pour les logs.
func (s *Session) RemoteString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.remote == nil {
		return "?"
	}
	return s.remote.String()
}

// mkSession initialisé à partir de clés déjà dérivées (sens C2S/S2C selon rôle).
// Ne lance PAS reader() : le client l'ajoute, le serveur démuxe globalement.
func mkSession(conn *net.UDPConn, remote *net.UDPAddr, keys *SessionKeys, serverSide bool) *Session {
	s := &Session{
		conn:     conn,
		remote:   remote,
		isServer: serverSide,
		die:      make(chan struct{}),
		closed:   make(chan struct{}),
		unacked:  make(map[uint32]*seg),
		rxSeen:   make(map[uint32]bool),
		fastRetr: make(map[uint32]int),
		sndWnd:   4096,
		cwnd:     defaultCWND,
		srtt:     float64(initRTO.Microseconds()),
		rttvar:   float64(initRTO.Microseconds()) / 2,
		lastRX:   time.Now(),
		mux:      nil,
	}
	if serverSide {
		tx, rx := keys.S2C, keys.C2S
		s.key = &tx
		s.txKey = tx
		s.rxKey = rx
	} else {
		tx, rx := keys.C2S, keys.S2C
		s.key = &tx
		s.txKey = tx
		s.rxKey = rx
	}
	copy(s.token[:], s.txKey[:tokenLen])

	s.mux = newMux(s)
	go s.ticker()
	return s
}

func equalCt(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func randByte() byte { var b [1]byte; rand.Read(b[:]); return b[0] }

// rto calcule le RTO courant (Jacobson/Karels).
func (s *Session) rto() time.Duration {
	rto := s.srtt + maxF(clockGran(), 4*s.rttvar)
	d := time.Duration(rto) * time.Microsecond
	if d < minRTO {
		d = minRTO
	}
	return d
}
func clockGran() float64 { return 10 * 1000 } // granularité 10 ms (µs)
func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// ── Envoi fiable ─────────────────────────────────────────────────────────

// SendType envoie un payload fiable (TypeData = frames mux).
func (s *Session) sendData(payload []byte) error {
	if err := s.queue(TypeData, payload); err != nil {
		return err
	}
	s.bytesOut.Add(int64(len(payload)))
	return nil
}

func (s *Session) queue(typ uint8, payload []byte) error {
	s.mu.Lock()
	if s.dead {
		s.mu.Unlock()
		return ErrSessionClosed
	}
	seq := s.txSeq
	s.txSeq++
	heap.Push(&s.unackedQ, &seg{seq: seq, typ: typ, data: payload})
	s.mu.Unlock()
	return nil
}

// flush émet selon fenêtre/pacing. Appelé par le ticker et au RX d'ACK.
// forceRetransmit marque tous les segments en vol comme « à retransmettre
// immédiatement » : leur sentAt est reculé pour que le prochain flush()
// (appelé juste après handle()) les réémette sans attendre le RTO.
// Appelé à la réception d'un ping (port hopping : fenêtre de transition).
func (s *Session) forceRetransmit() {
	now := time.Now()
	for _, seg := range s.unacked {
		if seg.xmit > 0 {
			seg.sentAt = now.Add(-10 * time.Minute) // dépasse tout RTO
		}
	}
}

func (s *Session) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead {
		return
	}
	now := time.Now()
	ack, bits := s.rxAckState()

	// pacing simple : espace de (srtt/cwnd) entre émissions
	spacing := time.Duration(s.srtt/s.cwnd) * time.Microsecond
	inflight := s.inflight // segments émis & non acquittés
	toSend := 0
	for s.unackedQ.Len() > 0 {
		peek := s.unackedQ[0]
		// Segment déjà acquitté (retiré de la map par processAck) : on le
		// purge silencieusement de la heap.
		if peek.xmit > 0 {
			if _, ok := s.unacked[peek.seq]; !ok {
				heap.Pop(&s.unackedQ)
				continue
			}
		}
		needRetrans := peek.xmit == 0 ||
			now.Sub(peek.sentAt) > s.rto() ||
			s.fastRetr[peek.seq] >= 3

		if !needRetrans {
			break
		}
		if peek.xmit > 0 {
			s.retrs.Add(1) // retransmission réseau (pertes) — diagnostic
		}
		// Fenêtre de congestion (premiers envois ET retransmissions) et
		// plafond absolu de la fenêtre d'émission.
		if inflight >= int(s.cwnd) || inflight >= s.sndWnd {
			break
		}
		if toSend > 0 && spacing > 0 && !s.lastPace.IsZero() && now.Sub(s.lastPace) < spacing {
			break
		}
		heap.Pop(&s.unackedQ)
		wnd := uint16(s.recvWindowAvail())
		pkt := encodePacket(&s.txKey, &s.token, peek.typ, 0, wnd, peek.seq, ack, bits, peek.data)
		if _, err := s.conn.WriteToUDP(pkt, s.remote); err == nil {
			peek.xmit++
			peek.sentAt = now
			s.lastTX = now
			s.lastPace = now
			if peek.xmit == 1 {
				s.inflight++
				inflight++
				toSend++
			} else {
				delete(s.fastRetr, peek.seq)
			}
		}
		s.unacked[peek.seq] = peek
		// Re-push : le ticker reviendra pour la retransmission RTO.
		heap.Push(&s.unackedQ, peek)
	}

	// Données reçues à acquitter et rien d'émis pour les porter : on envoie
	// un pure-ack (64B) — sinon l'émetteur retransmettrait en aveugle.
	if s.ackPend && toSend == 0 {
		ack, bits = s.rxAckState()
		pkt := encodePacket(&s.txKey, &s.token, TypePureAck, 0, uint16(rcvWindow), s.txSeq, ack, bits, nil)
		if _, err := s.conn.WriteToUDP(pkt, s.remote); err == nil {
			s.lastTX = now
			s.ackPend = false
		}
	}
}

// rxAckState : ACK cumulatif honnête (frontière contiguë) + SACK des
// arrivées hors-ordre AU-DESSUS de la frontière (bit i ⇔ rxBase+i reçu).
func (s *Session) rxAckState() (ack uint32, bits uint32) {
	ack = s.rxBase
	for i := uint32(1); i <= 32; i++ {
		if s.rxSeen[s.rxBase+i] {
			bits |= 1 << (i - 1)
		}
	}
	return
}

func (s *Session) recvWindowAvail() int {
	return rcvWindow
}

// ── Réception ────────────────────────────────────────────────────────────

func (s *Session) curConn() *net.UDPConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

// Retarget change UNIQUEMENT la destination (s.remote) en gardant la
// même socket source. C'est le mécanisme de port hopping de la doc
// officielle Hysteria 2 : "the client will randomly select one of the
// specified ports for the initial connection and will periodically
// switch to a different port... the hopping process is transparent to
// the upper layers and should not cause any data loss/disconnection."
//
// Le port SOURCE reste stable : un seul mapping CGNAT, les réponses du
// serveur reviennent toujours vers la même socket. Le port DESTINATION
// hoppe dans la plage DNAT : l'opérateur qui bloque/trie un flux UDP
// persistant sur un port donné voit un flux différent à chaque hop.
// L'ancien SwapConn (nouvelle socket source) cassait le downlink derrière
// un CGNAT : les réponses n'étaient plus routées vers le nouveau mapping.
func (s *Session) Retarget(addr *net.UDPAddr) {
	s.mu.Lock()
	s.remote = addr
	s.mu.Unlock()
}

// SwapConn remplace la socket UDP sous-jacente (rotation du port source,
// conservée pour compatibilité — le port hopping par défaut est désormais
// Retarget, qui préserve la socket source et le mapping CGNAT).
func (s *Session) SwapConn(c *net.UDPConn) {
	s.mu.Lock()
	old := s.conn
	s.conn = c
	s.mu.Unlock()
	if old != nil {
		// DRAIN avant fermeture : les réponses du serveur encore en vol
		// dans le buffer de réception de l'ancienne socket sont des
		// données downlink réelles. Les fermer les perd (le CGNAT du
		// réseau mobile droppe ensuite le port mort) — on les récupère
		// pendant une fenêtre courte puis on ferme.
		go func() {
			old.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buf := make([]byte, 4096)
			for {
				n, from, err := old.ReadFromUDP(buf)
				if err != nil || n == 0 {
					break
				}
				if n >= MinPktLen {
					s.handle(from, append([]byte(nil), buf[:n]...))
				}
			}
			old.Close()
		}()
	}
}

// Conn retourne la socket courante (usage tests/diagnostic).
func (s *Session) Conn() *net.UDPConn { return s.curConn() }

func (s *Session) reader() {
	buf := make([]byte, 4096)
	for {
		c := s.curConn()
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			s.mu.Lock()
			swapped := s.conn != c
			dead := s.dead
			s.mu.Unlock()
			if swapped && !dead {
				continue // socket remplacée : on repart sur la nouvelle
			}
			s.kill()
			return
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		s.handle(from, raw)
	}
}

func (s *Session) handle(from *net.UDPAddr, raw []byte) {
	typ, flags, _, seq, ack, bits, payload, err := decodePacket(&s.rxKey, raw)
	if err != nil {
		s.pktsBad.Add(1)
		return
	}
	s.pktsIn.Add(1)
	s.mu.Lock()
	prevRemote := s.remote
	s.remote = from // suit le port-hopping
	s.lastRX = time.Now()
	s.mu.Unlock()
	if prevRemote != nil && prevRemote.String() != from.String() {
		// Le port hopping DESTINATION de l'app : l'IP du client reste
		// STABLE (une socket), mais le port externe CGNAT change par
		// destination (mapping port-dependent) — seul l'adresse
		// COMPLÈTE (IP+port) détecte le changement de mapping. L'ancien
		// trigger (IP seul) ne tirait JAMAIS la purge.
		s.onPairChange(prevRemote)
	}

	// Traitement des ACKs émis par le pair
	s.processAck(ack, bits)

	switch typ {
	case TypeData:
		if s.seenIsNew(seq) {
			// livraison fiable : dédup au niveau session, réordonnancement
			// par stream via les séquences internes du mux.
			s.mu.Lock()
			s.ackPend = true
			s.mu.Unlock()
			s.bytesIn.Add(int64(len(payload)))
			s.mux.deliver(payload)
		}
	case TypeUDPData:
		if s.onUDPPacket != nil {
			s.bytesIn.Add(int64(len(payload)))
			s.onUDPPacket(payload)
		}
	case TypePureAck:
		// Keepalive reçu sans réponse = seul l'émetteur survit. On répond
		// un pong (flags=1) — le pong ne déclenche pas de réponse (boucle).
		if flags == 0 {
			s.sendUDPRaw(TypePureAck, 1, nil)
			if !s.isServer {
				// Pong reçu par le client : RTT = maintenant - le dernier
				// ping (la latence réelle du chemin — diagnostic kighmu).
				if lp := s.lastPing.Load(); lp > 0 {
					rtt := (time.Now().UnixNano() - lp) / int64(time.Millisecond)
					s.lastRTT.Store(rtt)
				}
			}
		}
		// Ping = le client est vivant : ses segments en vol ont pu
		// être perdus dans la fenêtre de transition du port hopping
		// (le conntrack re-écrit le mapping à chaque hop) — sans
		// retransmission immédiate ils attendaient le RTO (300 ms+)
		// et le trafic repartait un segment PAR HOP (log kighmu :
		// "DATA sid1 sseq=0/1/2" un seul par hop, out serveur figé).
		// On force la retransmission de TOUT l'en vol dès le ping.
		s.forceRetransmit()
	}
	s.flush()
}

// seenIsNew : enregistre seq côté RX ; retourne vrai s'il est nouveau,
// faux s'il s'agit d'un doublon dû à la fiabilisation.
// seenIsNew : livre un seq de session la première fois qu'il est vu.
// Le point cumulatif rxBase n'avance QUE sur le flux contigu livré —
// le hors-ordre est bufferisé (rxSeen) et signalé par SACK bitmask,
// jamais par l'ACK cumulatif (sinon l'émetteur abandonnerait les
// segments manquants sous-jacents).
func (s *Session) seenIsNew(seq uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := int32(seq - s.rxBase)
	switch {
	case d == 0: // in-order : avance à travers le contigu bufferisé
		s.rxBase++
		for s.rxSeen[s.rxBase] {
			delete(s.rxSeen, s.rxBase)
			s.rxBase++
		}
		return true
	case d > 0: // hors-ordre : bufferise sans avancer le cumulatif
		if s.rxSeen[seq] {
			return false
		}
		s.rxSeen[seq] = true
		return true
	default: // d < 0 : déjà couvert par le cumulatif (retransmission)
		return false
	}
}

// processAck : purge les segments ackés, mesure RTT, congestion control.
func (s *Session) processAck(ack uint32, bits uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rttNow := time.Now()

	// Plus bas seq en vol avant traitement (pour triple-ACK dupliqué).
	var lowestBefore int64 = -1
	if s.unackedQ.Len() > 0 {
		if top := s.unackedQ[0]; top.xmit > 0 {
			if _, ok := s.unacked[top.seq]; ok {
				lowestBefore = int64(top.seq)
			}
		}
	}

	try := func(seq uint32) {
		if sg, ok := s.unacked[seq]; ok {
			if sg.xmit == 1 {
				rtt := float64(rttNow.Sub(sg.sentAt).Microseconds())
				s.rttAck(rtt)
			}
			if sg.xmit >= 1 {
				s.inflight--
				if s.inflight < 0 {
					s.inflight = 0
				}
			}
			s.onAcked()
			delete(s.unacked, seq)
			delete(s.fastRetr, seq)
		}
	}
	// cumulatif : tout < ack (frontière contiguë honnête)
	for seq := range s.unacked {
		if int32(seq-ack) < 0 {
			try(seq)
		}
	}
	// SACK bitmask : ack+1 .. ack+32 reçus hors-ordre
	for i := uint32(1); i <= 32; i++ {
		if bits&(1<<(i-1)) != 0 {
			try(ack + i)
		}
	}

	// Triple-ACK : le plus bas seq en vol n'a pas progressé → retrans
	// rapide imminente (flush enverra dès que fastRetr >= 3).
	if s.unackedQ.Len() > 0 && lowestBefore >= 0 {
		if top := s.unackedQ[0]; top.seq == uint32(lowestBefore) {
			if _, ok := s.unacked[top.seq]; ok {
				s.fastRetr[top.seq]++
				if s.fastRetr[top.seq] > 8 {
					s.fastRetr[top.seq] = 8
				}
			}
		}
	}
}

func (s *Session) rttAck(rtt float64) {
	if s.srtt == 0 {
		s.srtt = rtt
		s.rttvar = rtt / 2
		return
	}
	d := rtt - s.srtt
	if d < 0 {
		d = -d
	}
	s.rttvar = 0.75*s.rttvar + 0.25*d
	s.srtt = 0.875*s.srtt + 0.125*rtt
}

// onAcked : slow-start puis AIMD (≈ Reno adouci, plus agressif que TCP).
func (s *Session) onAcked() {
	if s.cwnd < 64 { // slow-start : +1 par segment acké
		s.cwnd++
	} else { // congestion avoidance : +1/cwnd
		s.cwnd += 1 / s.cwnd
	}
	if s.cwnd > maxCWND {
		s.cwnd = maxCWND
	}
}

// onLoss : appelé lors d'une retransmission RTO-détectée.
func (s *Session) onLoss() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cwnd *= 0.7
	if s.cwnd < 4 {
		s.cwnd = 4
	}
}

// ── ticker maintenance ───────────────────────────────────────────────────

func (s *Session) ticker() {
	t := time.NewTicker(10 * time.Millisecond)
	ka := time.NewTicker(keepalive)
	to := time.NewTicker(2 * time.Second)
	defer t.Stop()
	defer ka.Stop()
	defer to.Stop()
	var lastLossCheck time.Time
	for {
		select {
		case <-s.die:
			return
		case <-t.C:
			s.flush()
			// détection de pertes RTO toutes les 25 ms
			if time.Since(lastLossCheck) > 25*time.Millisecond && s.rtoExpired() {
				s.onLoss()
			}
			lastLossCheck = time.Now()
		case <-ka.C:
			// Résistance aux pertes CGNAT (capture tcpdump : ~95% des
			// paquets "spontanés" perdus, seul l'échange immédiat passe) :
			// 3 pings espacés de 150 ms par tick — le mapping change à
			// chaque paquet sortant, au moins un ping part sur le mapping
			// frais et déclenche la retransmission serveur + le pong.
			// Dans une goroutine : ne pas bloquer la boucle flush (10ms).
			go func() {
				for i := 0; i < 3; i++ {
					s.sendUDPRaw(TypePureAck, 0, nil)
					time.Sleep(150 * time.Millisecond)
				}
			}()
		case <-to.C:
			s.mu.Lock()
			idle := time.Since(s.lastRX)
			s.mu.Unlock()
			if idle > sessTimeout {
				s.kill()
				return
			}
		}
	}
}

func (s *Session) rtoExpired() bool {
	now := time.Now()
	rto := s.rto()
	for seg := range s.unacked {
		if now.Sub(s.unacked[seg].sentAt) > rto {
			return true
		}
	}
	return false
}

// sendUDPRaw envoie un paquet unique (datagramme, fiable=non).
func (s *Session) sendUDPRaw(typ uint8, flags uint8, payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead {
		return
	}
	// PADDING QUIC (anti-blocage opérateur, SANS dépendance) : la spec
	// QUIC (RFC 9000 §14.1) impose des paquets Initial de 1200 octets
	// MINIMUM — les opérateurs (DPI/CGNAT) traitent ces tailles comme du
	// trafic légitime. Nos paquets (56-130 B) étaient classés "petits
	// paquets UDP vers ports hauts" = flood/scan, et le flux entier
	// bloqué après 1-2 paquets (715 paquets serveur envoyés, AUCUN reçu ;
	// le zivpn/QUIC avec ses paquets 1200+ B passe sur le même réseau).
	// Fix : chaque paquet est paddé à 1200-1330 B aléatoires — les
	// mêmes tailles que QUIC. Le récepteur ignore le trailing garbage :
	// decodePacket retourne le payload brut, le mux parse les frames
	// séquentiellement (trailing garbage jamais lu).
	var pad [1330]byte
	rand.Read(pad[:])                                            // crypto/rand : jamais en erreur sur Linux
	minPad := 1200 - (8 + nonceLen + 16 + hdrLen + len(payload)) // jusqu'à ~1200 total
	if minPad < 8 {
		minPad = 8
	}
	nPad := minPad + int(pad[0])%130
	payload = append(append([]byte(nil), payload...), pad[:nPad]...)
	ack, bits := s.rxAckState()
	wnd := uint16(s.recvWindowAvail())
	pkt := encodePacket(&s.txKey, &s.token, typ, flags, wnd, s.txSeq, ack, bits, payload)
	s.conn.WriteToUDP(pkt, s.remote)
	s.lastTX = time.Now()
}

// SendKeepalive : ping immédiat (après hop de port, pour que le serveur
// mette à jour l'adresse du pair dès la nouvelle socket).
func (s *Session) SendKeepalive() {
	s.lastPing.Store(time.Now().UnixNano()) // le pong mesurera le RTT
	s.sendUDPRaw(TypePureAck, 0, nil)
}

// SendBadUDP / datagramme non fiable (DNS, jeux…).
func (s *Session) SendDatagram(payload []byte) { s.sendUDPRaw(TypeUDPData, 0, payload) }

// routeFlush : flag conservé pour lecture depuis mux (réservé).
var _ = binary.BigEndian

// HandleFromServer : point d'entrée côté serveur (reader démux global).
func (s *Session) HandleFromServer(from *net.UDPAddr, raw []byte) { s.handle(from, raw) }

// RespondHandshake : après validation d'un handshake1 (ParseHandshake1),
// génère l'éphémère serveur, dérive les clés, répond handshake2 et
// instancie la session serveur prête à recevoir HandleFromServer.
func RespondHandshake(conn *net.UDPConn, from *net.UDPAddr, psk []byte, clientEph *[32]byte) (*Session, error) {
	s, _, err := respondHandshakeH2(conn, from, psk, clientEph)
	return s, err
}

// respondHandshakeH2 : comme RespondHandshake, mais retourne aussi les
// octets handshake2 — le registre de handshakes les retransmet tels quels
// lors d'une réémission de handshake1 (mêmes clés, aucun re-handshake).
func respondHandshakeH2(conn *net.UDPConn, from *net.UDPAddr, psk []byte, clientEph *[32]byte) (*Session, []byte, error) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		return nil, nil, err
	}
	shared, err := dh(&priv, clientEph)
	if err != nil {
		return nil, nil, err
	}
	keys := deriveKeys(&shared, psk)
	confirm := HandshakeConfirm(&keys.C2S, clientEph)
	h2 := BuildHandshake2(&pub, confirm)
	// PADDING QUIC (RFC 9000 §14.1) : 1200+ octets MINIMUM — la réponse
	// serveur est paddée comme un paquet QUIC Initial légitime.
	var pad2 [1300]byte
	rand.Read(pad2[:])
	h2 = append(h2, pad2[:]...)
	if _, err := conn.WriteToUDP(h2, from); err != nil {
		return nil, nil, err
	}
	return mkSession(conn, from, keys, true), h2, nil
}

// Mux retourne le multiplexeur de streams.
func (s *Session) Mux() *Mux { return s.mux }

func (s *Session) kill() {
	s.mu.Lock()
	if s.dead {
		s.mu.Unlock()
		return
	}
	s.dead = true
	close(s.die)
	s.mu.Unlock()
	s.mux.closeAll()
	close(s.closed)
}

// Close termine la session.
func (s *Session) Close() {
	s.sendUDPRaw(TypeCloseSess, 0, nil)
	s.kill()
}

// LocalAddr / RemoteAddr pour l'interface net.Conn-like.
func (s *Session) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *Session) RemoteAddr() net.Addr { return s.remote }

// routeFlush : champs utilisés par handle() puis flush().
