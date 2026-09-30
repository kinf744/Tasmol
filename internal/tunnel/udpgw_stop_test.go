package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	"vpn-app/internal/config"
)

// Stop() used to hold u.mu across u.wg.Wait(). handlePackets unblocks from
// ReadFrom when the connection is closed and then needs u.mu to record the
// error, so the wait could never complete: Stop blocked forever, u.status
// stayed true, and every later Stop/Start/GetStats blocked too.
func TestUDPGWProxyStopDoesNotDeadlock(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("udp unavailable: %v", err)
	}

	u := &udpgwProxy{
		config: config.UDPGWConfig{Enabled: true, MTU: 1400},
		conn:   pc,
		stats:  UDPGWStats{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.ctx, u.cancel = ctx, cancel
	u.status = true
	u.wg.Add(1)
	go u.handlePackets()

	done := make(chan struct{})
	go func() {
		_ = u.Stop(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("udpgwProxy.Stop deadlocked (wg.Wait under u.mu)")
	}

	if u.status {
		t.Error("status still true after Stop")
	}
	// A second Stop must be a cheap no-op, not a second hang.
	second := make(chan struct{})
	go func() {
		_ = u.Stop(context.Background())
		close(second)
	}()
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		t.Fatal("second udpgwProxy.Stop blocked")
	}
}

// wg.Add used to be called from the read loop, which could race the
// wg.Wait() in Stop and panic with "sync: WaitGroup misuse" (Go >= 1.20),
// killing the process. The read loop now registers under u.mu and refuses
// once Stop has begun, so Stop must survive a burst of real traffic.
func TestUDPGWProxyStopUnderTraffic(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("udp unavailable: %v", err)
	}
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		t.Skipf("udp dial unavailable: %v", err)
	}

	u := &udpgwProxy{
		config: config.UDPGWConfig{Enabled: true, MTU: 1400},
		conn:   pc,
		stats:  UDPGWStats{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.ctx, u.cancel = ctx, cancel
	u.status = true
	u.wg.Add(1)
	go u.handlePackets()

	// Keep the read loop busy registering forwarders right up to the Stop.
	stop := make(chan struct{})
	go func() {
		payload := make([]byte, 256)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = client.Write(payload)
			time.Sleep(time.Millisecond)
		}
	}()

	time.Sleep(150 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		_ = u.Stop(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("udpgwProxy.Stop deadlocked under traffic")
	}
	close(stop)
	client.Close()
}
