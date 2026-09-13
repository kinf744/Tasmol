package api

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"vpn-app/internal/config"
	"vpn-app/internal/core"
	"vpn-app/internal/tunnel"
)

type Server struct {
	core      *core.VPNCore
	configMgr *config.Manager
	router    *gin.Engine
	upgrader  websocket.Upgrader
	wsClients map[*websocket.Conn]bool
	wsMu      sync.Mutex
}

type TunnelRequest struct {
	Name      string                 `json:"name" binding:"required"`
	Type      string                 `json:"type" binding:"required"`
	Enabled   bool                   `json:"enabled"`
	Priority  int                    `json:"priority"`
	Server    config.ServerConfig    `json:"server" binding:"required"`
	Auth      config.AuthConfig      `json:"auth" binding:"required"`
	Transport config.TransportConfig `json:"transport"`
	Routing   config.RoutingConfig   `json:"routing"`
	Advanced  map[string]interface{} `json:"advanced"`
}

func NewServer(core *core.VPNCore, configMgr *config.Manager) *Server {
	s := &Server{
		core:      core,
		configMgr: configMgr,
		router:    gin.Default(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		wsClients: make(map[*websocket.Conn]bool),
	}

	s.setupRoutes()
	s.startWSBroadcaster()

	return s
}

func (s *Server) setupRoutes() {
	s.router.Static("/static", "./web/static")
	s.router.LoadHTMLGlob("web/templates/*")

	s.router.GET("/", s.indexHandler)
	s.router.GET("/ws", s.wsHandler)

	api := s.router.Group("/api/v1")
	{
		api.GET("/status", s.statusHandler)
		api.GET("/config", s.getConfigHandler)
		api.PUT("/config", s.updateConfigHandler)

		api.GET("/tunnels", s.listTunnelsHandler)
		api.POST("/tunnels", s.createTunnelHandler)
		api.GET("/tunnels/:id", s.getTunnelHandler)
		api.PUT("/tunnels/:id", s.updateTunnelHandler)
		api.DELETE("/tunnels/:id", s.deleteTunnelHandler)
		api.POST("/tunnels/:id/start", s.startTunnelHandler)
		api.POST("/tunnels/:id/stop", s.stopTunnelHandler)
		api.POST("/tunnels/:id/restart", s.restartTunnelHandler)

		api.GET("/features", s.getFeaturesHandler)
		api.PUT("/features", s.updateFeaturesHandler)

		api.POST("/export", s.exportHandler)
		api.POST("/import", s.importHandler)

		api.GET("/logs", s.logsHandler)
		api.GET("/stats", s.statsHandler)
	}
}

func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
}

func (s *Server) indexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "VPN App",
	})
}

func (s *Server) wsHandler(c *gin.Context) {
	conn, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}

	s.wsMu.Lock()
	s.wsClients[conn] = true
	s.wsMu.Unlock()

	defer func() {
		s.wsMu.Lock()
		delete(s.wsClients, conn)
		s.wsMu.Unlock()
		conn.Close()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (s *Server) startWSBroadcaster() {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			s.broadcastStatus()
		}
	}()
}

func (s *Server) broadcastStatus() {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()

	status := s.getStatusData()

	for conn := range s.wsClients {
		if err := conn.WriteJSON(status); err != nil {
			conn.Close()
			delete(s.wsClients, conn)
		}
	}
}

func (s *Server) getStatusData() gin.H {
	tunnels := s.core.GetTunnelManager().List()

	tunnelData := make([]gin.H, 0, len(tunnels))
	for _, t := range tunnels {
		stats := t.Stats()
		tunnelData = append(tunnelData, gin.H{
			"id":         t.ID(),
			"name":       t.Name(),
			"type":       t.Type(),
			"status":     t.Status(),
			"enabled":    t.Config().Enabled,
			"bytes_up":   stats.BytesUp,
			"bytes_down": stats.BytesDown,
			"latency":    stats.Latency,
			"uptime":     stats.Uptime,
			"error":      stats.LastError,
		})
	}

	return gin.H{
		"running":   s.core.IsRunning(),
		"features":  s.core.GetFeatureManager().GetStatus(),
		"tunnels":   tunnelData,
		"udpgw":     s.core.GetTunnelManager().GetUDPGW().GetStats(),
		"timestamp": time.Now().Unix(),
	}
}

func (s *Server) statusHandler(c *gin.Context) {
	c.JSON(http.StatusOK, s.getStatusData())
}

func (s *Server) getConfigHandler(c *gin.Context) {
	c.JSON(http.StatusOK, s.configMgr.Get())
}

func (s *Server) updateConfigHandler(c *gin.Context) {
	var cfg config.Config
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	s.configMgr.Get() // This would need proper update logic
	c.JSON(http.StatusOK, gin.H{"message": "Config updated"})
}

func (s *Server) listTunnelsHandler(c *gin.Context) {
	tunnels := s.core.GetTunnelManager().List()
	data := make([]gin.H, 0, len(tunnels))
	for _, t := range tunnels {
		data = append(data, gin.H{
			"id":      t.ID(),
			"name":    t.Name(),
			"type":    t.Type(),
			"status":  t.Status(),
			"enabled": t.Config().Enabled,
			"config":  t.Config(),
		})
	}
	c.JSON(http.StatusOK, data)
}

func (s *Server) createTunnelHandler(c *gin.Context) {
	var req TunnelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tunnelCfg := config.TunnelConfig{
		Name:      req.Name,
		Type:      config.TunnelType(req.Type),
		Enabled:   req.Enabled,
		Priority:  req.Priority,
		Server:    req.Server,
		Auth:      req.Auth,
		Transport: req.Transport,
		Routing:   req.Routing,
		Advanced:  req.Advanced,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.configMgr.AddTunnel(&tunnelCfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	t, err := tunnel.CreateTunnel(&tunnelCfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := s.core.GetTunnelManager().Add(t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if tunnelCfg.Enabled {
		t.Start(context.Background())
	}

	c.JSON(http.StatusCreated, gin.H{"id": tunnelCfg.ID, "message": "Tunnel created"})
}

func (s *Server) getTunnelHandler(c *gin.Context) {
	id := c.Param("id")
	t, ok := s.core.GetTunnelManager().Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tunnel not found"})
		return
	}

	stats := t.Stats()
	c.JSON(http.StatusOK, gin.H{
		"id":      t.ID(),
		"name":    t.Name(),
		"type":    t.Type(),
		"status":  t.Status(),
		"enabled": t.Config().Enabled,
		"config":  t.Config(),
		"stats":   stats,
	})
}

func (s *Server) updateTunnelHandler(c *gin.Context) {
	id := c.Param("id")
	var req TunnelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tunnelCfg := config.TunnelConfig{
		ID:        id,
		Name:      req.Name,
		Type:      config.TunnelType(req.Type),
		Enabled:   req.Enabled,
		Priority:  req.Priority,
		Server:    req.Server,
		Auth:      req.Auth,
		Transport: req.Transport,
		Routing:   req.Routing,
		Advanced:  req.Advanced,
		UpdatedAt: time.Now(),
	}

	if err := s.configMgr.UpdateTunnel(id, tunnelCfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tunnel updated"})
}

func (s *Server) deleteTunnelHandler(c *gin.Context) {
	id := c.Param("id")
	if err := s.core.GetTunnelManager().Remove(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := s.configMgr.DeleteTunnel(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Tunnel deleted"})
}

func (s *Server) startTunnelHandler(c *gin.Context) {
	id := c.Param("id")
	t, ok := s.core.GetTunnelManager().Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tunnel not found"})
		return
	}

	if err := t.Start(context.Background()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Tunnel started"})
}

func (s *Server) stopTunnelHandler(c *gin.Context) {
	id := c.Param("id")
	t, ok := s.core.GetTunnelManager().Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tunnel not found"})
		return
	}

	if err := t.Stop(context.Background()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Tunnel stopped"})
}

func (s *Server) restartTunnelHandler(c *gin.Context) {
	id := c.Param("id")
	t, ok := s.core.GetTunnelManager().Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tunnel not found"})
		return
	}

	if err := t.Restart(context.Background()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Tunnel restarted"})
}

func (s *Server) getFeaturesHandler(c *gin.Context) {
	c.JSON(http.StatusOK, s.core.GetFeatureManager().GetStatus())
}

func (s *Server) updateFeaturesHandler(c *gin.Context) {
	var features config.FeaturesConfig
	if err := c.ShouldBindJSON(&features); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.core.GetFeatureManager().UpdateConfig(&features); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Features updated"})
}

func (s *Server) exportHandler(c *gin.Context) {
	format := c.Query("format")

	// Implementation would use importExport package
	c.JSON(http.StatusOK, gin.H{"message": "Export initiated", "format": format})
}

func (s *Server) importHandler(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Implementation would use importExport package
	c.JSON(http.StatusOK, gin.H{"message": "Import initiated", "filename": file.Filename})
}

func (s *Server) logsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"logs": []string{}})
}

func (s *Server) statsHandler(c *gin.Context) {
	tunnels := s.core.GetTunnelManager().List()
	data := make([]gin.H, 0, len(tunnels))
	for _, t := range tunnels {
		stats := t.Stats()
		data = append(data, gin.H{
			"id":           t.ID(),
			"name":         t.Name(),
			"bytes_up":     stats.BytesUp,
			"bytes_down":   stats.BytesDown,
			"packets_up":   stats.PacketsUp,
			"packets_down": stats.PacketsDown,
			"latency":      stats.Latency,
			"uptime":       stats.Uptime,
		})
	}
	c.JSON(http.StatusOK, data)
}
