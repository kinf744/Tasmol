package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"gopkg.in/yaml.v3"
	"vpn-app/internal/api"
	"vpn-app/internal/config"
	"vpn-app/internal/core"
)

var (
	version = "1.0.0"
	commit  = "dev"
	date    = "unknown"
)

func main() {
	var (
		configPath  = flag.String("config", "", "Path to config file")
		dataDir     = flag.String("data-dir", "", "Data directory")
		webPort     = flag.Int("port", 0, "Web UI port")
		webHost     = flag.String("host", "", "Web UI host")
		showVersion = flag.Bool("version", false, "Show version")
		exportPath  = flag.String("export", "", "Export config to file")
		importPath  = flag.String("import", "", "Import config from file")
		password    = flag.String("password", "", "Password for encrypt/decrypt")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("VPN App v%s (%s) built at %s\n", version, commit, date)
		os.Exit(0)
	}

	defaultConfigPath := getDefaultConfigPath(*dataDir)
	if *configPath == "" {
		configPath = &defaultConfigPath
	}

	configMgr, err := config.NewManager(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	defer configMgr.Close()

	cfg := configMgr.Get()

	if *dataDir != "" {
		cfg.App.DataDir = *dataDir
	}
	if *webPort != 0 {
		cfg.App.WebPort = *webPort
	}
	if *webHost != "" {
		cfg.App.WebHost = *webHost
	}

	if *exportPath != "" {
		exporter := NewExporter(configMgr, *password)
		if err := exporter.ExportToFile(*exportPath); err != nil {
			fmt.Fprintf(os.Stderr, "Export failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Config exported to %s\n", *exportPath)
		os.Exit(0)
	}

	if *importPath != "" {
		importer := NewImporter(configMgr, *password)
		if err := importer.ImportFromFile(*importPath); err != nil {
			fmt.Fprintf(os.Stderr, "Import failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Config imported from %s\n", *importPath)
		os.Exit(0)
	}

	vpnCore, err := core.NewVPNCore(configMgr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create VPN core: %v\n", err)
		os.Exit(1)
	}

	server := api.NewServer(vpnCore, configMgr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		cancel()
	}()

	if err := vpnCore.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start VPN: %v\n", err)
		os.Exit(1)
	}

	addr := fmt.Sprintf("%s:%d", cfg.App.WebHost, cfg.App.WebPort)
	fmt.Printf("VPN App started on %s\n", addr)
	fmt.Printf("Web UI: http://%s\n", addr)

	if err := server.Run(addr); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}

	vpnCore.Stop(ctx)
}

func getDefaultConfigPath(dataDir string) string {
	if dataDir != "" {
		return filepath.Join(dataDir, "config.yaml")
	}
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".vpn-app", "config.yaml")
}

type Exporter struct {
	configManager *config.Manager
	password      string
}

type Importer struct {
	configManager *config.Manager
	password      string
}

func NewExporter(cm *config.Manager, password string) *Exporter {
	return &Exporter{configManager: cm, password: password}
}

func NewImporter(cm *config.Manager, password string) *Importer {
	return &Importer{configManager: cm, password: password}
}

func (e *Exporter) ExportToFile(path string) error {
	data, err := e.configManager.Export()
	if err != nil {
		return err
	}
	content, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, 0644)
}

func (i *Importer) ImportFromFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return i.configManager.ImportYAML(content)
}
