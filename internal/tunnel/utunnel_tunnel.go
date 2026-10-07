package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"vpn-app/internal/config"
)

// UtunnelTunnel drives the utunnel client binary (shipped in the repository
// bundle as bin/armv7/utunnel and staged as lib_utunnel.so on Android):
//
//	utunnel-client -server <ip:port> -key-file <file> \
//	    -socks 127.0.0.1:<livePort> -hop-port-every <N>
//
// utunnel est un tunnel UDP PROPRIÉTAIRE (aucune dépendance Hysteria/QUIC) :
//   - fiabilisation ARQ sélective (ACK cumulatif honnête + SACK bitmask 32,
//     triple-ACK, RTO Jacobson min 80 ms, slow-start + AIMD, pacing srtt/cwnd) ;
//   - chiffrement X25519 éphémère + XChaCha20-Poly1305, clés dérivées par
//     HKDF-SHA3 informées du PSK ;
//   - port-hopping par ROTATION DE SOCKET (le serveur suit l'adresse:port
//     du pair à chaque paquet — la plage DNAT-ée côté serveur est traversée
//     gratuitement, aucun re-handshake) ;
//   - multiplexage TCP + relais UDP dans un seul flux de session.
//
// Le client expose SOCKS5 sur 127.0.0.1:<livePort> (port frais par session,
// même convention que les autres tunnels).
//
// Profil requis (config): server.host, server.port (port RÉEL d'écoute du
// serveur — ex. 5669 ; la plage clients 40000-45999 est DNAT-ée côté
// serveur, jamais dialée par le client), auth.password (PSK).
// Avancés optionnels: utunnel_hop (int, secondes entre deux rotations de
// port source, 0 = jamais, défaut 10), socks_port (override du port SOCKS).
type UtunnelTunnel struct {
	mu        sync.RWMutex
	config    *config.TunnelConfig
	status    Status
	stats     Stats
	cancel    context.CancelFunc
	startTime time.Time

	cmd     *exec.Cmd
	keyPath string
}

func NewUtunnelTunnel(cfg *config.TunnelConfig) *UtunnelTunnel {
	return &UtunnelTunnel{config: cfg, status: StatusStopped}
}

func (t *UtunnelTunnel) ID() string              { return t.config.ID }
func (t *UtunnelTunnel) Name() string            { return t.config.Name }
func (t *UtunnelTunnel) Type() config.TunnelType { return config.TunnelUtunnel }

func (t *UtunnelTunnel) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}

func (t *UtunnelTunnel) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s := t.stats
	if t.status == StatusRunning {
		s.Uptime = int64(time.Since(t.startTime).Seconds())
	}
	return s
}

func (t *UtunnelTunnel) Config() *config.TunnelConfig { return t.config }

// resolveServerIP résout le hostname en IP d'abord : le client Go ne peut
// pas se fier au DNS Android depuis un processus enfant (pattern Picko).
func (t *UtunnelTunnel) resolveServerIP() string {
	host := strings.TrimSpace(t.config.Server.Host)
	if host == "" {
		return host
	}
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	if addr, err := net.ResolveIPAddr("ip", host); err == nil && addr != nil {
		return addr.String()
	}
	return host
}

// resolveClientKey détermine la clé client transmise au binaire :
//   - champ de 64 caractères hexadécimaux  -> clé directe (mode avancé) ;
//   - toute autre valeur                   -> SHA256 du secret (hex), ce qui
//     correspond exactement à la dérivation du serveur (server.psk en clair
//     -> SHA256) ET au mode users.list stivaros (uuid|secret : la valeur
//     saisie est alors déjà le résultat attendu côté serveur).
//
// Le champ brut n'est JAMAIS journalisé : seul sa longueur/dérivation l'est.
func resolveClientKey(secret string) (key string, derived bool) {
	secret = strings.TrimSpace(secret)
	if len(secret) == 64 && isHex64(secret) {
		return strings.ToLower(secret), false
	}
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:]), true
}

func isHex64(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// DefaultUtunnelHopInterval : secondes entre deux rotations du port source.
// Le serveur suit le pair à chaque paquet, donc la rotation est gratuite ;
// elle casse la visibilité des flux UDP longs côté DPI.
const DefaultUtunnelHopInterval = 10

func (t *UtunnelTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	Tracef("[utunnel] Start() begin status=%s name=%q", t.status, t.config.Name)

	if t.status == StatusRunning {
		Tracef("[utunnel] already running, skip")
		return nil
	}
	host := strings.TrimSpace(t.config.Server.Host)
	secret := strings.TrimSpace(t.config.Auth.Password)
	if host == "" || secret == "" {
		err := fmt.Errorf("utunnel: server.host et auth.password (PSK) sont requis")
		Errorf("utunnel", "%v", err)
		return err
	}
	port := t.config.Server.Port
	if port <= 0 {
		port = 5669 // port d'écoute réel par défaut du serveur utunnel
	}

	t.status = StatusStarting
	t.setError("")
	ClearLiveSocksAddr(t.config.ID)

	ctx, t.cancel = context.WithCancel(ctx)

	bin := LookupBin(BinDir, BinUtunnel)
	ip := t.resolveServerIP()
	server := fmt.Sprintf("%s:%d", ip, port)

	key, derived := resolveClientKey(secret)
	Tracef("[utunnel] clé client: %s (%d octets) dérivée=%v",
		map[bool]string{true: "SHA256", false: "directe"}[derived], len(key)/2, derived)

	// Port SOCKS frais par session (même convention que zivpn/hysteria).
	socksAddr, socksPort, err := PickLiveSocksAddr(t.config)
	if err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	if err := waitPortFreeCtx(ctx, socksPort, 4*time.Second); err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	hop := advInt(t.config.Advanced, "utunnel_hop", DefaultUtunnelHopInterval)
	if hop < 0 {
		hop = 0
	}

	// Clé écrite dans un fichier temporaire 0600 : jamais dans les
	// arguments de processus (visibles via /proc/<pid>/cmdline).
	keyPath := fmt.Sprintf("%s/utunnel-%s.key", TmpDir, t.config.ID)
	if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
		t.status = StatusError
		t.setError(fmt.Sprintf("clé: %v", err))
		Errorf("utunnel", "écriture clé: %v", err)
		return err
	}
	t.keyPath = keyPath

	Journalf("utunnel", "udp %s (socks %s, hop %ds)", server, socksAddr, hop)
	Tracef("[utunnel] binaire=%q pid à venir, tmp=%s", bin, TmpDir)

	// UTUNNEL_TRACE=1 : le binaire journalise les premiers frames mux
	// (op/sid/seq) — diagnostic des liens très perturbés, dans kighmu.txt.
	cmd := exec.CommandContext(ctx, bin,
		"-server", server,
		"-key-file", keyPath,
		"-socks", socksAddr,
		"-hop-port-every", fmt.Sprintf("%d", hop),
	)
	cmd.Dir = TmpDir
	cmd.Env = append(os.Environ(),
		"UTUNNEL_TRACE=1",
		"HOME="+TmpDir,
		"TMPDIR="+TmpDir,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.cleanupFiles()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.cleanupFiles()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	if err := cmd.Start(); err != nil {
		t.cleanupFiles()
		t.status = StatusError
		t.setError(fmt.Sprintf("utunnel start failed: %v", err))
		Errorf("utunnel", "exec start failed: %v", err)
		return fmt.Errorf("failed to start utunnel client: %w", err)
	}
	t.cmd = cmd
	Tracef("[utunnel] process started pid=%d", cmd.Process.Pid)
	Infof("utunnel", "client lancé pid=%d (serveur %s)", cmd.Process.Pid, server)
	go PipeLinesToLog(stdout, "[utunnel][out]")
	go PipeLinesToLog(stderr, "[utunnel][err]")
	go t.watchProcess(cmd)

	// Readiness : le handshake (X25519+PSK) doit aboutir et le SOCKS local
	// répondre (15 s comme hysteria).
	if err := waitForTCPctx(ctx, socksAddr, 15*time.Second); err != nil {
		t.killLocked()
		t.status = StatusError
		t.setError(fmt.Sprintf("utunnel socks not ready (handshake/PSK ?): %v", err))
		Errorf("utunnel", "SOCKS %s not ready (handshake ou PSK invalide ?): %v", socksAddr, err)
		return fmt.Errorf("utunnel socks not ready: %w", err)
	}
	SetLiveSocksAddr(t.config.ID, socksAddr)

	t.startTime = time.Now()
	t.status = StatusRunning
	Tracef("[utunnel] RUNNING name=%q socks=%s", t.config.Name, socksAddr)
	Connf("utunnel", "connecté %s (UDP, ARQ+XChaCha)", server)
	return nil
}

// watchProcess flips the tunnel to error when the child dies unexpectedly.
func (t *UtunnelTunnel) watchProcess(cmd *exec.Cmd) {
	err := cmd.Wait()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cmd != cmd {
		return // arrêt propre (Stop a déjà nettoyé)
	}
	if t.status == StatusRunning || t.status == StatusStarting {
		t.status = StatusError
		t.setError(fmt.Sprintf("utunnel exited: %v", err))
		Errorf("utunnel", "process exited: %v", err)
	}
}

func (t *UtunnelTunnel) cleanupFiles() {
	if t.keyPath != "" {
		_ = os.Remove(t.keyPath)
		t.keyPath = ""
	}
}

func (t *UtunnelTunnel) killLocked() {
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
		_, _ = t.cmd.Process.Wait()
	}
	t.cmd = nil
	if t.keyPath != "" {
		_ = os.Remove(t.keyPath)
		t.keyPath = ""
	}
}

func (t *UtunnelTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusStopped {
		return nil
	}
	t.status = StatusStopping
	Infof("utunnel", "arrêt du client")
	if t.cancel != nil {
		t.cancel()
	}
	ClearLiveSocksAddr(t.config.ID)
	t.killLocked()
	t.status = StatusStopped
	return nil
}

func (t *UtunnelTunnel) Restart(ctx context.Context) error {
	if err := t.Stop(ctx); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return t.Start(ctx)
}

func (t *UtunnelTunnel) setError(msg string) {
	t.stats.LastError = msg
	t.stats.UpdatedAt = time.Now()
}
