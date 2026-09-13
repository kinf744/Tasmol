package tunnel

import (
	"context"
	"time"

	"vpn-app/internal/config"
)

type Status string

const (
	StatusStopped  Status = "stopped"
	StatusStarting Status = "starting"
	StatusRunning  Status = "running"
	StatusStopping Status = "stopping"
	StatusError    Status = "error"
)

type Stats struct {
	BytesUp     int64     `json:"bytes_up"`
	BytesDown   int64     `json:"bytes_down"`
	PacketsUp   int64     `json:"packets_up"`
	PacketsDown int64     `json:"packets_down"`
	Latency     int64     `json:"latency_ms"`
	Uptime      int64     `json:"uptime_seconds"`
	LastError   string    `json:"last_error,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Tunnel interface {
	ID() string
	Name() string
	Type() config.TunnelType
	Status() Status
	Stats() Stats
	Config() *config.TunnelConfig
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Restart(ctx context.Context) error
}

type Manager interface {
	Add(tunnel Tunnel) error
	Remove(id string) error
	Get(id string) (Tunnel, bool)
	List() []Tunnel
	GetRunning() []Tunnel
	StartAll(ctx context.Context) error
	StopAll(ctx context.Context) error
	GetUDPGW() UDPGW
	OnStatusChange(func(Tunnel, Status))
	OnStatsUpdate(func(Tunnel, Stats))
}

type UDPGWConfig struct {
	Enabled    bool
	ListenAddr string
	MaxClients int
	Timeout    int
	MTU        int
}

type UDPGW interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	IsRunning() bool
	GetStats() UDPGWStats
}

type UDPGWStats struct {
	ActiveConnections int   `json:"active_connections"`
	TotalConnections  int64 `json:"total_connections"`
	BytesReceived     int64 `json:"bytes_received"`
	BytesSent         int64 `json:"bytes_sent"`
	Errors            int64 `json:"errors"`
}
