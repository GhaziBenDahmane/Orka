package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bendahma/dokploy-go/internal/agent"
	"github.com/bendahma/dokploy-go/internal/config"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/httpapi"
	dockyardmigrate "github.com/bendahma/dokploy-go/internal/migrate"
	"github.com/bendahma/dokploy-go/internal/observability"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/bendahma/dokploy-go/internal/templates"
	"github.com/google/uuid"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dockyard <serve|agent|import-dokploy-templates|validate-dokploy-templates|migrate-dokploy>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve()
	case "agent":
		err = runAgent()
	case "import-dokploy-templates":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: dockyard import-dokploy-templates PATH")
			os.Exit(2)
		}
		err = importTemplates(os.Args[2])
	case "validate-dokploy-templates":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: dockyard validate-dokploy-templates PATH")
			os.Exit(2)
		}
		report, validationErr := templates.ValidateDokployCatalog(os.Args[2], deploy.Compiler{PublicNetwork: "dockyard-public"})
		_ = json.NewEncoder(os.Stdout).Encode(report)
		err = validationErr
	case "migrate-dokploy":
		err = migrateDokploy(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: dockyard <serve|agent|import-dokploy-templates|validate-dokploy-templates|migrate-dokploy>")
		os.Exit(2)
	}
	if err != nil {
		slog.Error("dockyard stopped", "error", err)
		os.Exit(1)
	}
}

func runAgent() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return agent.Run(ctx, agent.Config{
		EnrollmentURL:       os.Getenv("DOCKYARD_CONTROL_PLANE_URL"),
		AgentURL:            os.Getenv("DOCKYARD_AGENT_URL"),
		EnrollmentToken:     os.Getenv("DOCKYARD_AGENT_ENROLLMENT_TOKEN"),
		EnrollmentTokenFile: os.Getenv("DOCKYARD_AGENT_ENROLLMENT_TOKEN_FILE"),
		StateDirectory:      envDefault("DOCKYARD_AGENT_STATE_DIRECTORY", "/var/lib/dockyard-agent"),
		DockerBin:           envDefault("DOCKYARD_DOCKER_BIN", "docker"),
		Network:             envDefault("DOCKYARD_TRAEFIK_NETWORK", "dockyard-public"),
		Version:             version,
		ServiceName:         envDefault("DOCKYARD_AGENT_SERVICE_NAME", "dockyard-agent_agent"),
	})
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func migrateDokploy(arguments []string) error {
	flags := flag.NewFlagSet("migrate-dokploy", flag.ContinueOnError)
	sourceURL := flags.String("source-url", "", "Dokploy PostgreSQL connection URL")
	sourceOrganization := flags.String("source-organization", "", "Dokploy organization ID")
	targetOrganization := flags.String("target-organization", "", "Dockyard organization UUID")
	dryRun := flags.Bool("dry-run", true, "validate and report without writing")
	keyFile := flags.String("encryption-key-file", "", "Dokploy exportEncryptionKeys file")
	registryPrefix := flags.String("registry-prefix", "", "OCI registry repository prefix for imported Git applications")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	targetID, err := uuid.Parse(*targetOrganization)
	if err != nil {
		return errors.New("--target-organization must be a UUID")
	}
	keys := [][]byte{}
	if *keyFile != "" {
		data, readErr := os.ReadFile(*keyFile)
		if readErr != nil {
			return readErr
		}
		keys, err = dockyardmigrate.ParseDokployKeys(data)
		if err != nil {
			return err
		}
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	box, err := cryptox.New(cfg.MasterKey)
	if err != nil {
		return err
	}
	report, err := dockyardmigrate.ImportDokploy(ctx, db, box, deploy.Compiler{PublicNetwork: cfg.TraefikNetwork, AllowUnsafe: cfg.UnsafeWorkloads}, dockyardmigrate.DokployOptions{SourceURL: *sourceURL, SourceOrganizationID: *sourceOrganization, TargetOrganizationID: targetID, RegistryPrefix: *registryPrefix, DryRun: *dryRun, EncryptionKeys: keys})
	_ = json.NewEncoder(os.Stdout).Encode(report)
	return err
}

func importTemplates(path string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	report, err := templates.ImportDokployCatalog(ctx, db, path)
	_ = json.NewEncoder(os.Stdout).Encode(report)
	return err
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownTracing, err := observability.InitTracing(ctx, observability.TraceConfig{Endpoint: cfg.OTLPEndpoint, Insecure: cfg.OTLPInsecure, Service: cfg.ServiceName, Version: version})
	if err != nil {
		return fmt.Errorf("initialize OpenTelemetry: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := shutdownTracing(shutdownCtx); err != nil {
			logger.Error("shutdown OpenTelemetry", "error", err)
		}
	}()
	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	box, err := cryptox.New(cfg.MasterKey)
	if err != nil {
		return err
	}
	compiler := deploy.Compiler{PublicNetwork: cfg.TraefikNetwork, AllowUnsafe: cfg.UnsafeWorkloads}
	swarm := deploy.Swarm{DockerBin: cfg.DockerBin, Network: cfg.TraefikNetwork, Timeout: 5 * time.Minute}
	databaseRegistry := database.NewRegistry()
	metrics := observability.NewMetrics()
	worker := &deploy.Worker{Store: db, Box: box, Compiler: compiler, Swarm: swarm, Concurrency: cfg.WorkerConcurrency, Logger: logger, ID: uuid.NewString(), Databases: databaseRegistry, BackupDirectory: cfg.BackupDirectory, Builder: deploy.Builder{GitBin: "git", DockerBin: cfg.DockerBin}, Metrics: metrics}
	worker.RemoteScheduler = func(clusterID uuid.UUID) deploy.Scheduler {
		return deploy.RemoteSwarm{Store: db, Box: box, ClusterID: clusterID, Timeout: 45 * time.Minute}
	}
	go worker.Run(ctx)
	api := &httpapi.Server{Store: db, Box: box, Compiler: compiler, Databases: databaseRegistry, Swarm: swarm, SessionTTL: cfg.SessionTTL, Logger: logger, PublicURL: cfg.PublicURL, Metrics: metrics, AgentCACertificate: cfg.AgentCACertificate, AgentCAKey: cfg.AgentCAKey, AgentCertificateTTL: cfg.AgentCertificateTTL}
	httpServer := &http.Server{Addr: cfg.ListenAddr, Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	servers := []*http.Server{httpServer}
	var agentServer *http.Server
	if cfg.AgentListenAddr != "" {
		clientCAs, tlsErr := httpapi.AgentTLSConfig(cfg.AgentCACertificate)
		if tlsErr != nil {
			return tlsErr
		}
		agentServer = &http.Server{Addr: cfg.AgentListenAddr, Handler: api.AgentHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 35 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 2 * time.Minute, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}}
		servers = append(servers, agentServer)
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, server := range servers {
			_ = server.Shutdown(shutdownCtx)
		}
	}()
	logger.Info("dockyard listening", "address", cfg.ListenAddr)
	serverErrors := make(chan error, len(servers))
	go func() { serverErrors <- httpServer.ListenAndServe() }()
	if agentServer != nil {
		logger.Info("dockyard agent API listening", "address", cfg.AgentListenAddr)
		go func() { serverErrors <- agentServer.ListenAndServeTLS(cfg.AgentServerCertFile, cfg.AgentServerKeyFile) }()
	}
	err = <-serverErrors
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	stop()
	return err
}
