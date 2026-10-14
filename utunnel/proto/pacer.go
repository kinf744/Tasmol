package proto

import (
	"io"
	"sync"
	"time"
)

// Pacer : un token bucket à débit fixe — le mode "Brutal" (adapté à un
// débit cible). Sur les réseaux mobiles lossy/CGNAT, le CC loss-based
// (CUBIC) s'effondre ; le pacing à débit cible maintient le débit dès
// lors que la cible est réellement disponible. Pacer est nil-safe :
// toutes les méthodes sont des no-ops si le pacer vaut nil.
type Pacer struct {
	mu     sync.Mutex
	bps    float64
	tokens float64
	burst  float64
	last   time.Time
}

// NewPacer : mbps <= 0 → nil (pas de pacing).
func NewPacer(mbps float64) *Pacer {
	if mbps <= 0 {
		return nil
	}
	bps := mbps * 1e6 / 8
	return &Pacer{
		bps:    bps,
		tokens: bps / 10,           // départ : 100 ms de crédit
		burst:  bps / 4,            // plafond : 250 ms de crédit
		last:   time.Now(),
	}
}

// Wait : bloque jusqu'à ce que n octets de crédit soient disponibles.
func (p *Pacer) Wait(n int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	need := float64(n)
	for {
		now := time.Now()
		p.tokens += now.Sub(p.last).Seconds() * p.bps
		if p.tokens > p.burst {
			p.tokens = p.burst
		}
		p.last = now
		if need <= p.tokens {
			p.tokens -= need
			return
		}
		miss := (need - p.tokens) / p.bps
		sleep := time.Duration(miss * float64(time.Second))
		if sleep > 50*time.Millisecond {
			sleep = 50 * time.Millisecond // réactif : ré-évalue par tranches
		}
		p.mu.Unlock()
		time.Sleep(sleep)
		p.mu.Lock()
	}
}

// PacedWriter : un io.Writer qui consomme du crédit avant chaque write
// (branchable directement dans io.Copy).
type PacedWriter struct {
	W io.Writer
	P *Pacer
}

func (pw *PacedWriter) Write(b []byte) (int, error) {
	if pw.P == nil {
		return pw.W.Write(b)
	}
	pw.P.Wait(len(b))
	return pw.W.Write(b)
}
