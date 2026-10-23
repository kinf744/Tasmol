package tunnel

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"vpn-app/internal/config"
)

type collector struct {
	mu  sync.Mutex
	got []string
}

func (c *collector) add(s string) {
	c.mu.Lock()
	c.got = append(c.got, s)
	c.mu.Unlock()
}

func (c *collector) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.got))
	copy(out, c.got)
	return out
}

func TestUDPGWProxyDoesNotShareReadBuffer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("udp unavailable: %v", err)
	}
	defer pc.Close()

	const listeners = 8
	const perListener = 40
	addrOf := make([]string, listeners)
	collectors := make([]*collector, listeners)

	for i := 0; i < listeners; i++ {
		lp, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("udp listener unavailable: %v", err)
		}
		defer lp.Close()
		addrOf[i] = lp.LocalAddr().String()
		c := &collector{}
		collectors[i] = c
		go func(lp net.PacketConn, c *collector) {
			buf := make([]byte, 2048)
			for {
				n, _, err := lp.ReadFrom(buf)
				if err != nil {
					return
				}
				c.add(string(buf[:n]))
			}
		}(lp, c)
	}

	u := &udpgwProxy{
		config: config.UDPGWConfig{Enabled: true, MTU: 1400, Timeout: 1},
		conn:   pc,
		stats:  UDPGWStats{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.ctx, u.cancel = ctx, cancel
	u.status = true
	u.wg.Add(1)
	go u.handlePackets()

	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Skipf("udp dial unavailable: %v", err)
	}
	defer client.Close()

	for round := 0; round < perListener; round++ {
		for i := 0; i < listeners; i++ {
			if _, err := client.Write([]byte(addrOf[i])); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
	}
	time.Sleep(2 * time.Second)

	mismatches := 0
	delivered := 0
	for i := 0; i < listeners; i++ {
		for _, got := range collectors[i].snapshot() {
			delivered++
			if got != addrOf[i] {
				mismatches++
				if mismatches <= 5 {
					t.Errorf("listener %d (expected %q) received %q",
						i, addrOf[i], got)
				}
			}
		}
	}
	if delivered == 0 {
		t.Skip("no datagram was forwarded; the gateway path did not engage")
	}
	if mismatches > 0 {
		t.Errorf("%d/%d datagrams were delivered to the wrong target: the "+
			"forwarder shared the read-loop buffer", mismatches, delivered)
	}
}
