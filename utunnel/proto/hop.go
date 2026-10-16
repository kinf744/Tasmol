package proto

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

// ── HopPacketConn : le port hopping à la Hysteria v1 ────────────────────
//
// Le mécanisme qui fait passer le zivpn/hysteria là où un client QUIC
// simple meurt : à chaque hop, un NOUVEAU socket local est créé (nouveau
// port source → NOUVEAU mapping CGNAT) et la destination tourne dans la
// plage serveur, PENDANT QUE la connexion QUIC migre (les Connection IDs
// survivent — quic-go accepte la migration de chemin). L'ancien socket
// reste vivant le temps de la transition (zéro perte à la couture).
//
// Côté serveur : quic-go accepte les paquets du même CID depuis une
// nouvelle adresse de source (migration de chemin) et répond à la
// dernière adresse vue — le conntrack de chaque nouveau mapping fait
// le reste.

const (
	hopQueueSize = 512
	hopPrevGrace = 6 * time.Second // l'ancien socket écoute encore après le hop
	hopServerTTL = 0               // les candidats serveurs restent valides
)

type hopPacket struct {
	buf  []byte
	n    int
	addr net.Addr
}

type HopPacketConn struct {
	mu          sync.Mutex
	serverAddrs []net.Addr
	addrIdx     int
	hopInterval time.Duration
	newConn     func() (net.PacketConn, error) // fabrique : socket local + obfs

	prev    net.PacketConn
	prevEnd time.Time
	current net.PacketConn

	recvQueue chan hopPacket
	closeChan chan struct{}
	closeOnce sync.Once
	closed    bool
	hopping   bool
}

// NewHopPacketConn : serverAddrs = les destinations candidates (une par
// classe de ports), newConn = la fabrique d'un socket local obfusqué.
// serverAddrs nil → dérivé de la plage "ip:c1,c2-c3,…" : UN port
// aléatoire PAR CLASSE (le random plein-frange, pas b[0]%…).
func NewHopPacketConn(serverAddrs []net.Addr, hopInterval time.Duration, newConn func() (net.PacketConn, error)) *HopPacketConn {
	if hopInterval <= 0 {
		hopInterval = 10 * time.Second
	}
	c := &HopPacketConn{
		serverAddrs: serverAddrs,
		hopInterval: hopInterval,
		newConn:     newConn,
		recvQueue:   make(chan hopPacket, hopQueueSize),
		closeChan:   make(chan struct{}),
	}
	return c
}

// SetServerAddrs : les destinations candidates (une par classe), à
// appeler avant Start().
func (c *HopPacketConn) SetServerAddrs(addrs []net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serverAddrs = addrs
	c.addrIdx = rand.Intn(len(addrs))
}

// CurrentServerAddr : la destination candidate courante (pour le dial).
func (c *HopPacketConn) CurrentServerAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.serverAddrs) == 0 {
		return &net.UDPAddr{}
	}
	return c.serverAddrs[c.addrIdx]
}

// Start : ouvre le premier socket SANS lancer la rotation — pendant la
// chasse, le socket doit rester STABLE (quic-go n'accepte pas la
// migration pendant le handshake : une rotation à 1,5 s tuait chaque
// handshake à mi-chemin). La rotation démarre avec StartRotation(),
// appelée APRÈS l'auth réussie.
func (c *HopPacketConn) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	pc, err := c.newConn()
	if err != nil {
		return err
	}
	c.current = pc
	go c.recvRoutine(pc)
	return nil
}

// StartRotation : lance le hopRoutine (la rotation locale+dest) —
// UNIQUEMENT après l'auth réussie.
func (c *HopPacketConn) StartRotation() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.hopping {
		return
	}
	c.hopping = true
	go c.hopRoutine()
}

func (c *HopPacketConn) hopRoutine() {
	ticker := time.NewTicker(c.hopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.hop()
		case <-c.closeChan:
			return
		}
	}
}

var _ = hopServerTTL

// hop : NOUVEAU socket local (nouveau mapping CGNAT) + destination
// suivante de la liste. L'ancien socket reste en écoute hopPrevGrace.
func (c *HopPacketConn) hop() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	pc, err := c.newConn()
	if err != nil {
		return // le hop suivant réessaiera
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		pc.Close()
		return
	}
	if c.prev != nil {
		c.prev.Close()
	}
	c.prev = c.current
	c.current = pc
	c.prevEnd = time.Now().Add(hopPrevGrace)
	c.addrIdx = (c.addrIdx + 1) % len(c.serverAddrs)
	go c.recvRoutine(pc)
	// La grâce : l'ancien socket reste ouvert jusqu'à prevEnd (les
	// dernières réponses du serveur y arrivent encore).
	go func(old net.PacketConn, end time.Time) {
		for time.Now().Before(end) {
			time.Sleep(500 * time.Millisecond)
			c.mu.Lock()
			done := c.closed || c.current != old && c.prev != old
			c.mu.Unlock()
			if done {
				break
			}
		}
		old.Close()
	}(c.prev, c.prevEnd)
}

func (c *HopPacketConn) recvRoutine(pc net.PacketConn) {
	buf := make([]byte, 65536)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := hopPacket{buf: make([]byte, n), n: n, addr: addr}
		copy(pkt.buf, buf[:n])
		select {
		case c.recvQueue <- pkt:
		case <-c.closeChan:
			return
		default:
			// La queue est pleine : jeter (le QUIC retransmettra).
		}
	}
}

func (c *HopPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		select {
		case p := <-c.recvQueue:
			n := copy(b, p.buf[:p.n])
			return n, p.addr, nil
		case <-c.closeChan:
			return 0, nil, net.ErrClosed
		}
	}
}

func (c *HopPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	cur := c.current
	idx := c.addrIdx
	c.mu.Unlock()
	_ = addr // toujours vers la destination candidate courante
	return cur.WriteTo(b, c.serverAddrs[idx])
}

func (c *HopPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.closed = true
		close(c.closeChan)
		if c.prev != nil {
			c.prev.Close()
		}
		if c.current != nil {
			c.current.Close()
		}
	})
	return nil
}

func (c *HopPacketConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return c.current.LocalAddr()
	}
	return &net.UDPAddr{}
}

// Les deadlines : portées par le stream QUIC (AuthStream) — no-op ici.
func (c *HopPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *HopPacketConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *HopPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *HopPacketConn) SetReadBuffer(n int) error          { return nil }
func (c *HopPacketConn) SetWriteBuffer(n int) error         { return nil }
