package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ── Multiplexage de streams sur la session fiable ───────────────────────
//
// Chaque frame mux dans un paquet TypeData :
//   [1B op][4B sid][4B seq][4B finSeq][2B len][payload]
//
// op :
//   0x01 OPEN   payload = "tcp:host:port" ou "udp:" (stream UDP-relay)
//   0x02 OK     serveur confirme l'ouverture
//   0x03 DATA   segment de données
//   0x04 FIN    demi-fermeture (fin d'écriture)
//   0x05 RST    erreur / fermeture forcée
//
// Chaque stream a ses propres compteurs de séquence indépendants du seq de
// session (qui sert à la fiabilisation) : l'ordre est rétabli par stream.

const maxFramePayload = 1100

var (
	muxOverhead = 14
	_           = muxOverhead
)

type Mux struct {
	s *Session

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextSID uint32 // client: impair, serveur: pair
	acceptQ chan *Stream

	// Dialer serveur : ouvre la cible finale (TCP/UDP).
	dialTCP   func(addr string) (net.Conn, error)
	onUDPOpen func(s *Stream)
}

func newMux(s *Session) *Mux {
	m := &Mux{
		s:       s,
		streams: make(map[uint32]*Stream),
		acceptQ: make(chan *Stream, 128),
	}
	if s.isServer {
		m.nextSID = 2
	} else {
		m.nextSID = 1
	}
	return m
}

// SetDialer (serveur) configure la résolution des cibles.
func (m *Mux) SetDialer(tcp func(addr string) (net.Conn, error), udpOpen func(s *Stream)) {
	m.dialTCP = tcp
	m.onUDPOpen = udpOpen
}

// Stream canal logique type net.Conn.
type Stream struct {
	m   *Mux
	sid uint32

	mu       sync.Mutex
	txSeq    uint32
	rxExpect uint32
	rxBuf    map[uint32][]byte
	readBuf  []byte
	rCond    *sync.Cond
	rEOF     bool
	closed   bool
	wfin     bool // demi-fermeture émetteur déjà envoyée
	finSet   bool // FIN reçu, en attente d'ordonnancement
	finSeq   uint32
	chOpen   chan error // handshake OPEN
}

// Open (client ou serveur-init) — ouvre un flux TCP vers addr.
func (m *Mux) Open(target string) (*Stream, error) {
	m.mu.Lock()
	sid := m.nextSID
	m.nextSID += 2
	st := newStream(m, sid)
	m.streams[sid] = st
	m.mu.Unlock()

	payload := []byte("tcp:" + target)
	if err := m.sendFrame(0x01, sid, 0, 0, payload); err != nil {
		m.removeStream(sid)
		return nil, err
	}
	select {
	case err := <-st.chOpen:
		if err != nil {
			m.removeStream(sid)
			return nil, err
		}
	case <-time.After(30 * time.Second):
		m.removeStream(sid)
		return nil, errors.New("timeout ouverture stream")
	}
	return st, nil
}

// OpenUDP ouvre un stream de relais datagrammes.
func (m *Mux) OpenUDP() (*Stream, error) {
	m.mu.Lock()
	sid := m.nextSID
	m.nextSID += 2
	st := newStream(m, sid)
	m.streams[sid] = st
	m.mu.Unlock()
	if err := m.sendFrame(0x01, sid, 0, 0, []byte("udp:")); err != nil {
		m.removeStream(sid)
		return nil, err
	}
	select {
	case err := <-st.chOpen:
		if err != nil {
			m.removeStream(sid)
			return nil, err
		}
	case <-time.After(30 * time.Second):
		m.removeStream(sid)
		return nil, errors.New("timeout ouverture stream UDP")
	}
	return st, nil
}

// Accept (serveur) : prochaine connexion TCP demandée.
func (m *Mux) Accept() (*Stream, error) {
	st, ok := <-m.acceptQ
	if !ok {
		return nil, ErrSessionClosed
	}
	return st, nil
}

func newStream(m *Mux, sid uint32) *Stream {
	st := &Stream{
		m:      m,
		sid:    sid,
		rxBuf:  make(map[uint32][]byte),
		chOpen: make(chan error, 1),
	}
	st.rCond = sync.NewCond(&st.mu)
	return st
}

// net.Conn-ish interface

func (st *Stream) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n := len(b)
		if n > maxFramePayload {
			n = maxFramePayload
		}
		// Séquence attribuée par trame sous verrou : des Writers
		// concurrents ne peuvent plus produire de seq en collision.
		st.mu.Lock()
		if st.closed {
			st.mu.Unlock()
			return total, ErrStreamClosed
		}
		if st.wfin {
			st.mu.Unlock()
			return total, ErrStreamClosed
		}
		seq := st.txSeq
		st.txSeq++
		st.mu.Unlock()

		if err := st.m.sendFrame(0x03, st.sid, seq, 0, b[:n]); err != nil {
			return total, err
		}
		total += n
		b = b[n:]
	}
	return total, nil
}

func (st *Stream) Read(b []byte) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for len(st.readBuf) == 0 && !st.rEOF && !st.closed {
		st.rCond.Wait()
	}
	if len(st.readBuf) > 0 {
		n := copy(b, st.readBuf)
		st.readBuf = st.readBuf[n:]
		return n, nil
	}
	if st.closed && len(st.readBuf) == 0 && !st.rEOF {
		return 0, io.ErrUnexpectedEOF
	}
	return 0, io.EOF
}

func (st *Stream) Close() error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	st.closed = true
	st.rEOF = true
	st.rCond.Broadcast()
	sendFin := !st.wfin
	st.wfin = true
	seq := st.txSeq
	st.txSeq++
	st.mu.Unlock()
	if sendFin {
		return st.m.sendFrame(0x04, st.sid, seq, 0, nil)
	}
	return nil
}

// CloseWrite signale une demi-fermeture : le FIN est transporté avec sa
// séquence pour que le récepteur ne le considère qu'après TOUTES les
// données qui le précèdent (indispensable sur un transport réordonnançant).
func (st *Stream) CloseWrite() error {
	st.mu.Lock()
	if st.wfin || st.closed {
		st.mu.Unlock()
		return nil
	}
	st.wfin = true
	seq := st.txSeq
	st.txSeq++
	st.mu.Unlock()
	return st.m.sendFrame(0x04, st.sid, seq, 0, nil)
}

func (st *Stream) resetWith(e error) {
	st.mu.Lock()
	st.closed = true
	st.rEOF = true
	st.rCond.Broadcast()
	st.mu.Unlock()
}

// ── traitement côté mux ──────────────────────────────────────────────────

const frameHdr = 16 // op1+sid4+seq4+finseq4+len2

func (m *Mux) sendFrame(op uint8, sid, seq, fin uint32, payload []byte) error {
	buf := make([]byte, frameHdr+len(payload))
	buf[0] = op
	binary.BigEndian.PutUint32(buf[1:], sid)
	binary.BigEndian.PutUint32(buf[5:], seq)
	binary.BigEndian.PutUint32(buf[9:], fin)
	binary.BigEndian.PutUint16(buf[13:], uint16(len(payload)))
	copy(buf[frameHdr:], payload)
	return m.s.sendData(buf)
}

// deliver traite un payload session (plusieurs frames concaténées possibles).
var dbgTrace = os.Getenv("UTUNNEL_TRACE") != ""
var dbgCount atomic.Int32

func dbgLog(format string, args ...any) {
	if !dbgTrace {
		return
	}
	if dbgCount.Add(1) < 40 {
		fmt.Fprintf(os.Stderr, "[TRACE] "+format+"\n", args...)
	}
}

func (m *Mux) deliver(payload []byte) {
	for len(payload) >= frameHdr {
		op := payload[0]
		sid := binary.BigEndian.Uint32(payload[1:])
		seq := binary.BigEndian.Uint32(payload[5:])
		ln := int(binary.BigEndian.Uint16(payload[13:]))
		if len(payload) < frameHdr+ln {
			return
		}
		data := payload[frameHdr : frameHdr+ln]
		m.dispatch(op, sid, seq, data)
		payload = payload[frameHdr+ln:]
	}
}

func (m *Mux) dispatch(op uint8, sid, seq uint32, data []byte) {
	if sid == 1 {
		dbgLog("disp op=%d sid=%d sseq=%d len=%d", op, sid, seq, len(data))
	}
	m.mu.Lock()
	st, ok := m.streams[sid]
	m.mu.Unlock()

	switch op {
	case 0x01: // OPEN (serveur uniquement)
		if !m.s.isServer {
			return
		}
		// IDEMPOTENT : l'ARQ peut réémettre le frame OPEN (ack perdu,
		// RTO). Réexpédier le flux écraserait l'existant et orphelinerait
		// le pont en cours : on ignore purement et simplement.
		m.mu.Lock()
		_, exists := m.streams[sid]
		m.mu.Unlock()
		if exists {
			return
		}
		target := string(data)
		st := newStream(m, sid)
		m.mu.Lock()
		m.streams[sid] = st
		m.mu.Unlock()
		if len(target) >= 4 && target[:4] == "udp:" {
			if m.onUDPOpen != nil {
				m.onUDPOpen(st)
			}
			m.sendFrame(0x02, sid, 0, 0, nil)
			return
		}
		addr := ""
		if len(target) >= 4 {
			addr = target[4:]
		}
		if m.dialTCP == nil {
			m.sendFrame(0x05, sid, 0, 0, []byte("pas de dialer"))
			return
		}
		conn, err := m.dialTCP(addr)
		if err != nil {
			m.sendFrame(0x05, sid, 0, 0, []byte(err.Error()))
			return
		}
		m.sendFrame(0x02, sid, 0, 0, nil)
		go bridgeTCP(st, conn)
		return

	case 0x02: // OK
		if ok && st.chOpen != nil {
			select {
			case st.chOpen <- nil:
			default:
			}
		}
		return
	case 0x05: // RST
		if ok {
			errTxt := "RST distant"
			if len(data) > 0 {
				errTxt = string(data)
			}
			if st.chOpen != nil {
				select {
				case st.chOpen <- errors.New(errTxt):
				default:
				}
			}
			st.resetWith(errors.New(errTxt))
			m.removeStream(sid)
		}
		return
	}

	if !ok {
		return
	}
	switch op {
	case 0x03: // DATA ordonné par stream
		st.mu.Lock()
		if sid == 1 {
			dbgLog("DATA sid1 sseq=%d rxExp=%d -> %s", seq, st.rxExpect, map[bool]string{true: "inorder", false: "buffer/drop"}[seq == st.rxExpect])
		}
		if seq == st.rxExpect {
			st.readBuf = append(st.readBuf, data...)
			st.rxAdvance()
		} else if int32(seq-st.rxExpect) > 0 {
			cp := make([]byte, len(data))
			copy(cp, data)
			st.rxBuf[seq] = cp
		}
		// séq inférieur = doublon dû à la fiabilisation : ignoré
		st.rCond.Broadcast()
		st.mu.Unlock()
	case 0x04: // FIN ordonné : n'agit qu'une fois les données livrées
		st.mu.Lock()
		if seq == st.rxExpect {
			st.rEOF = true
		} else if int32(seq-st.rxExpect) > 0 && !st.finSet {
			st.finSet, st.finSeq = true, seq
		}
		st.rCond.Broadcast()
		st.mu.Unlock()
	}
}

// rxAdvance (sous st.mu) : le frame in-order vient d'être appendé à
// readBuf — on avance le point contigu, on draine le buffer hors-ordre
// et on arme le FIN en attente lorsque la continuité l'atteint.
func (st *Stream) rxAdvance() {
	st.rxExpect++
	for {
		if nxt, ok := st.rxBuf[st.rxExpect]; ok {
			st.readBuf = append(st.readBuf, nxt...)
			delete(st.rxBuf, st.rxExpect)
			st.rxExpect++
			continue
		}
		if st.finSet && st.finSeq == st.rxExpect {
			st.rEOF = true
			st.finSet = false
		}
		return
	}
}

func (m *Mux) removeStream(sid uint32) {
	m.mu.Lock()
	delete(m.streams, sid)
	m.mu.Unlock()
}

func (m *Mux) closeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, st := range m.streams {
		st.mu.Lock()
		st.closed = true
		st.rEOF = true
		st.rCond.Broadcast()
		st.mu.Unlock()
	}
	m.streams = map[uint32]*Stream{}
	close(m.acceptQ)
}

// bridgeTCP pompe les DEUX sens indépendamment et ne ferme qu'une fois
// chacun terminé : fermer à la première fin de sens tronquerait l'autre.
func bridgeTCP(st *Stream, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() { // target -> stream
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := st.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				st.CloseWrite()
				break
			}
		}
	}()

	go func() { // stream -> target
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := st.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				if tc, okc := conn.(*net.TCPConn); okc {
					tc.CloseWrite()
				} else {
					conn.Close()
				}
				break
			}
		}
	}()

	wg.Wait()
	conn.Close()
	st.Close()
}

// Conn helpers
func (st *Stream) LocalAddr() net.Addr                { return st.m.s.LocalAddr() }
func (st *Stream) RemoteAddr() net.Addr               { return st.m.s.RemoteAddr() }
func (st *Stream) SetDeadline(t time.Time) error      { return nil }
func (st *Stream) SetReadDeadline(t time.Time) error  { return nil }
func (st *Stream) SetWriteDeadline(t time.Time) error { return nil }
