package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	"vpn-app/internal/config"
)

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
