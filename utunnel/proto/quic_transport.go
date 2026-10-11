package proto

import (
	"context"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// quicNetConn adapte une connexion QUIC (quic-go) à net.Conn — le
// transport PROUVÉ sur les réseaux mobiles hostiles (le DPI whitelist
// le QUIC : indistinguable du trafic HTTPS/3 légitime).
type quicNetConn struct {
	conn quic.Connection
	udp  *net.UDPConn // la socket locale (nil côté serveur)
}

// OpenSessionStream : le stream de session (le canal de données utunnel
// — les frames mux par-dessus, le même protocole).
func OpenSessionStream(q quic.Connection) (quic.Stream, error) {
	return q.OpenStreamSync(context.Background())
}

// AcceptSessionStream : accepte le stream de session (le serveur).
func AcceptSessionStream(q quic.Connection, d time.Duration) (quic.Stream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return q.AcceptStream(ctx)
}

// SendQUICDatagram : le datagramme QUIC (le relais UDP natif).
func SendQUICDatagram(q quic.Connection, b []byte) error {
	return q.SendDatagram(b)
}

// ReceiveQUICDatagram : réception d'un datagramme QUIC.
func ReceiveQUICDatagram(q quic.Connection) ([]byte, error) {
	return q.ReceiveDatagram(context.Background())
}

// CloseQUIC : ferme la connexion.
func CloseQUIC(q quic.Connection) {
	q.CloseWithError(0, "utunnel stop")
}
