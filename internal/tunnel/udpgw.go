package tunnel

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"

	"vpn-app/internal/config"
)

type udpgwImpl struct {
	mu        sync.RWMutex
	config    config.UDPGWConfig
	status    bool
	cmd       *exec.Cmd
	cancel    context.CancelFunc
	stats     UDPGWStats
	startTime time.Time
	listener  net.Listener
}

func NewUDPGW(cfg config.UDPGWConfig) UDPGW {
	return &udpgwImpl{
		config: cfg,
		status: false,
		stats:  UDPGWStats{},
	}
}

func (u *udpgwImpl) Start(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.status {
		return nil
	}

	if !u.config.Enabled {
		return fmt.Errorf("UDPGW is disabled in config")
	}

	ctx, u.cancel = context.WithCancel(ctx)

	args := []string{
		"--listen-addr", u.config.ListenAddr,
		"--max-clients", fmt.Sprintf("%d", u.config.MaxClients),
		"--timeout", fmt.Sprintf("%d", u.config.Timeout),
		"--mtu", fmt.Sprintf("%d", u.config.MTU),
		"--loglevel", u.config.LogLevel,
	}

	u.cmd = exec.CommandContext(ctx, LookupBin(BinDir, BinUDPGW), args...)

	if err := u.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start UDPGW: %w", err)
	}

	u.startTime = time.Now()
	u.status = true

	go u.monitorProcess()

	return nil
}

func (u *udpgwImpl) Stop(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if !u.status {
		return nil
	}

	if u.cancel != nil {
		u.cancel()
	}

	if u.cmd != nil && u.cmd.Process != nil {
		u.cmd.Process.Kill()
		u.cmd.Wait()
	}

	u.status = false
	return nil
}

func (u *udpgwImpl) IsRunning() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.status
}

func (u *udpgwImpl) GetStats() UDPGWStats {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.stats
}

func (u *udpgwImpl) monitorProcess() {
	err := u.cmd.Wait()
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.status {
		u.status = false
		if err != nil {
			u.stats.Errors++
		}
	}
}

type udpgwProxy struct {
	mu     sync.RWMutex
	config config.UDPGWConfig
	conn   net.PacketConn
	status bool
	stats  UDPGWStats
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewUDPGWProxy(cfg config.UDPGWConfig) UDPGW {
	return &udpgwProxy{
		config: cfg,
		stats:  UDPGWStats{},
	}
}

func (u *udpgwProxy) Start(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.status {
		return nil
	}

	if !u.config.Enabled {
		return fmt.Errorf("UDPGW is disabled in config")
	}

	u.ctx, u.cancel = context.WithCancel(ctx)

	addr, err := net.ResolveUDPAddr("udp", u.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDPGW address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDPGW address: %w", err)
	}

	u.conn = conn
	u.status = true

	u.wg.Add(1)
	go u.handlePackets()

	return nil
}

func (u *udpgwProxy) handlePackets() {
	defer u.wg.Done()

	buf := make([]byte, u.config.MTU)

	for {
		select {
		case <-u.ctx.Done():
			return
		default:
			u.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, clientAddr, err := u.conn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				u.mu.Lock()
				u.stats.Errors++
				u.mu.Unlock()
				continue
			}

			u.mu.Lock()
			u.stats.BytesReceived += int64(n)
			u.stats.ActiveConnections++
			u.mu.Unlock()

			// Register the forwarder under the mutex and refuse once Stop has
			// begun, so wg.Add can never race a concurrent wg.Wait().
			u.mu.Lock()
			if !u.status {
				u.mu.Unlock()
				return
			}
			// Hand the forwarder its OWN copy. buf is a single buffer reused
			// by this loop, and the forwarder reads it again after the
			// goroutine is scheduled (string(data) to resolve the target,
			// then Write(data) to the remote socket) — by which time the
			// next ReadFrom has already overwritten it. That corrupted
			// payloads and could mix bytes belonging to a different client
			// flow into this one. The copy must happen here, before we loop.
			payload := make([]byte, n)
			copy(payload, buf[:n])
			u.wg.Add(1)
			u.mu.Unlock()
			go u.forwardPacket(payload, clientAddr)
		}
	}
}

func (u *udpgwProxy) forwardPacket(data []byte, clientAddr net.Addr) {
	defer u.wg.Done()
	// handlePackets() increments ActiveConnections per datagram and only
	// decremented it on the success path, so the counter grew forever and
	// the UI showed a steadily rising number of "active" connections.
	defer func() {
		u.mu.Lock()
		if u.stats.ActiveConnections > 0 {
			u.stats.ActiveConnections--
		}
		u.mu.Unlock()
	}()

	targetAddr, err := net.ResolveUDPAddr("udp", string(data))
	if err != nil {
		u.mu.Lock()
		u.stats.Errors++
		u.mu.Unlock()
		return
	}

	targetConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		u.mu.Lock()
		u.stats.Errors++
		u.mu.Unlock()
		return
	}
	defer targetConn.Close()

	targetConn.SetDeadline(time.Now().Add(time.Duration(u.config.Timeout) * time.Second))

	if _, err := targetConn.Write(data); err != nil {
		u.mu.Lock()
		u.stats.Errors++
		u.mu.Unlock()
		return
	}

	response := make([]byte, u.config.MTU)
	targetConn.SetReadDeadline(time.Now().Add(time.Duration(u.config.Timeout) * time.Second))
	n, err := targetConn.Read(response)
	if err != nil {
		u.mu.Lock()
		u.stats.Errors++
		u.mu.Unlock()
		return
	}

	u.conn.WriteTo(response[:n], clientAddr)

	u.mu.Lock()
	u.stats.BytesSent += int64(n)
	u.stats.TotalConnections++
	u.mu.Unlock()
}

func (u *udpgwProxy) Stop(ctx context.Context) error {
	u.mu.Lock()
	if !u.status {
		u.mu.Unlock()
		return nil
	}
	// Flip the flag first: handlePackets re-checks it under this same mutex
	// before every wg.Add, so past this point no goroutine can register
	// itself and wg.Wait() can no longer race an Add — which panics with
	// "sync: WaitGroup misuse" on Go >= 1.20 and kills the process.
	u.status = false
	if u.cancel != nil {
		u.cancel()
	}
	conn := u.conn
	u.mu.Unlock()

	if conn != nil {
		conn.Close()
	}
	// wg.Wait() MUST run outside u.mu: the Close above unblocks handlePackets
	// from ReadFrom, and it then needs u.mu to record the error and the byte
	// counters. Holding the lock here made Stop wait forever on a goroutine
	// that could never make progress — and left u.status true, so every
	// later Stop (and Start) blocked too.
	u.wg.Wait()
	return nil
}

func (u *udpgwProxy) IsRunning() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.status
}

func (u *udpgwProxy) GetStats() UDPGWStats {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.stats
}
