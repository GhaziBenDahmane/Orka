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
		fmt.Fprintln(os.Stderr, "usage: dockyard <serve|agent|ai-auditor|import-dokploy-templates|validate-dokploy-templates|sign-template-catalog|migrate-dokploy|migrate-dokploy-data|verify-dokploy-import>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve()
	case "agent":
		err = runAgent()
	case "ai-auditor":
		err = runAIAuditor()
	case "import-dokploy-templates":
		err = importTemplates(os.Args[2:])
	case "sign-template-catalog":
		err = signTemplateCatalog(os.Args[2:])
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
	case "migrate-dokploy-data":
		err = migrateDokployData(os.Args[2:])
	case "verify-dokploy-import":
		err = verifyDokployImport(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: dockyard <serve|agent|ai-auditor|import-dokploy-templates|validate-dokploy-templates|sign-template-catalog|migrate-dokploy|migrate-dokploy-data|verify-dokploy-import>")
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
	sourceURL := flags.String("source-url", os.Getenv("DOCKYARD_DOKPLOY_DATABASE_URL"), "Dokploy PostgreSQL connection URL (or DOCKYARD_DOKPLOY_DATABASE_URL)")
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
	db.RequireRemoteBackups = cfg.RequireRemoteBackups
	box, err := cryptox.New(cfg.MasterKey)
	if err != nil {
		return err
	}
	report, err := dockyardmigrate.ImportDokploy(ctx, db, box, deploy.Compiler{PublicNetwork: cfg.TraefikNetwork, AllowUnsafe: cfg.UnsafeWorkloads}, dockyardmigrate.DokployOptions{SourceURL: *sourceURL, SourceOrganizationID: *sourceOrganization, TargetOrganizationID: targetID, RegistryPrefix: *registryPrefix, DryRun: *dryRun, EncryptionKeys: keys})
	_ = json.NewEncoder(os.Stdout).Encode(report)
	return err
}

func migrateDokployData(arguments []string) error {
	flags := flag.NewFlagSet("migrate-dokploy-data", flag.ContinueOnError)
	sourceURL := flags.String("source-url", os.Getenv("DOCKYARD_DOKPLOY_DATABASE_URL"), "Dokploy PostgreSQL connection URL (or DOCKYARD_DOKPLOY_DATABASE_URL)")
	sourceOrganization := flags.String("source-organization", "", "Dokploy organization ID")
	targetOrganization := flags.String("target-organization", "", "Dockyard organization UUID")
	connectionsFile := flags.String("connections-file", "", "mode-0600 JSON source connection manifest")
	dryRun := flags.Bool("dry-run", true, "validate and report without queuing transfers")
	confirm := flags.String("confirm", "", "target organization UUID required when --dry-run=false")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	targetID, err := uuid.Parse(*targetOrganization)
	if err != nil {
		return errors.New("--target-organization must be a UUID")
	}
	if *connectionsFile == "" {
		return errors.New("--connections-file is required")
	}
	info, err := os.Lstat(*connectionsFile)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("connections file must be a regular file with no group or other permissions")
	}
	data, err := os.ReadFile(*connectionsFile)
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("connections file exceeds 1 MiB")
	}
	manifest, err := dockyardmigrate.ParseDokployDatabaseTransferManifest(data)
	clear(data)
	if err != nil {
		return err
	}
	if !*dryRun && *confirm != targetID.String() {
		return errors.New("--confirm must exactly match --target-organization when queuing destructive data restores")
	}
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
	box, err := cryptox.New(cfg.MasterKey)
	if err != nil {
		return err
	}
	report, err := dockyardmigrate.QueueDokployDatabaseTransfers(ctx, db, box, dockyardmigrate.DokployOptions{SourceURL: *sourceURL, SourceOrganizationID: *sourceOrganization, TargetOrganizationID: targetID, DryRun: *dryRun}, manifest)
	if err == nil && !*dryRun {
		for _, item := range report.Items {
			db.AuditOrganization(ctx, targetID, "database_migration.queue", "database_migration", item.ID.String(), "cli", map[string]any{"sourceKind": item.SourceKind, "sourceId": item.SourceID, "databaseInstanceId": item.DatabaseInstanceID})
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
	return err
}

func verifyDokployImport(arguments []string) error {
	flags := flag.NewFlagSet("verify-dokploy-import", flag.ContinueOnError)
	sourceOrganization := flags.String("source-organization", "", "Dokploy organization ID used during import")
	targetOrganization := flags.String("target-organization", "", "Dockyard organization UUID")
	requireOperational := flags.Bool("require-operational", true, "require successful service deployments, running databases, and completed native data transfers")
	acknowledgements := stringValues{}
	flags.Var(&acknowledgements, "acknowledge", "acknowledge one documented manual conversion as kind:source-id (repeatable)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	targetID, err := uuid.Parse(*targetOrganization)
	if err != nil {
		return errors.New("--target-organization must be a UUID")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	report, err := dockyardmigrate.VerifyDokployImport(ctx, db, targetID, *sourceOrganization, *requireOperational, acknowledgements)
	_ = json.NewEncoder(os.Stdout).Encode(report)
	if err != nil {
		return err
	}
	if !report.Ready {
		return fmt.Errorf("Dokploy import verification blocked by %d resource checks", report.Blocked)
	}
	return nil
}

type stringValues []string

func (values *stringValues) String() string { return strings.Join(*values, ",") }
func (values *stringValues) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || !strings.Contains(value, ":") {
		return errors.New("acknowledgement must use kind:source-id")
	}
	*values = append(*values, value)
	return nil
}

func importTemplates(arguments []string) error {
	flags := flag.NewFlagSet("import-dokploy-templates", flag.ContinueOnError)
	publicKeyFile := flags.String("public-key-file", "", "trusted Ed25519 catalog public key")
	allowUnsigned := flags.Bool("allow-unsigned", false, "allow an unsigned catalog (development only)")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 1 {
		return errors.New("usage: dockyard import-dokploy-templates [--public-key-file PATH | --allow-unsigned] PATH")
	}
	if (*publicKeyFile == "") == !*allowUnsigned {
		return errors.New("exactly one of --public-key-file or --allow-unsigned is required")
	}
	path := flags.Arg(0)
	if *publicKeyFile != "" {
		key, err := templates.LoadPublicKey(*publicKeyFile)
		if err != nil {
			return err
		}
		if err = templates.VerifyCatalog(path, key); err != nil {
			return fmt.Errorf("verify template catalog: %w", err)
		}
	}
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

func signTemplateCatalog(arguments []string) error {
	flags := flag.NewFlagSet("sign-template-catalog", flag.ContinueOnError)
	privateKeyFile := flags.String("private-key-file", "", "Ed25519 catalog private key")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 1 || *privateKeyFile == "" {
		return errors.New("usage: dockyard sign-template-catalog --private-key-file PATH CATALOG_PATH")
	}
	key, err := templates.LoadPrivateKey(*privateKeyFile)
	if err != nil {
		return err
	}
	return templates.SignCatalog(flags.Arg(0), key)
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
	db.RequireRemoteBackups = cfg.RequireRemoteBackups
	if report, seedErr := templates.SeedBuiltinCatalog(ctx, db); seedErr != nil {
		return fmt.Errorf("seed built-in template catalog: %w", seedErr)
	} else {
		logger.Info("built-in template catalog ready", "templates", report.Imported)
	}
	if err = db.ValidateBackupConfiguration(ctx); err != nil {
		return fmt.Errorf("validate backup configuration: %w", err)
	}
	box, err := cryptox.New(cfg.MasterKey)
	if err != nil {
		return err
	}
	compiler := deploy.Compiler{PublicNetwork: cfg.TraefikNetwork, AllowUnsafe: cfg.UnsafeWorkloads}
	swarm := deploy.Swarm{DockerBin: cfg.DockerBin, Network: cfg.TraefikNetwork, Timeout: 5 * time.Minute}
	databaseRegistry := database.NewRegistry()
	if cfg.DatabaseDriverDirectory != "" {
		if err := databaseRegistry.LoadExternal(cfg.DatabaseDriverDirectory); err != nil {
			return fmt.Errorf("load external database drivers: %w", err)
		}
	}
	metrics := observability.NewMetrics()
	worker := &deploy.Worker{Store: db, Box: box, Compiler: compiler, Swarm: swarm, Concurrency: cfg.WorkerConcurrency, Logger: logger, ID: uuid.NewString(), Databases: databaseRegistry, BackupDirectory: cfg.BackupDirectory, Builder: deploy.Builder{GitBin: "git", DockerBin: cfg.DockerBin}, Metrics: metrics}
	worker.RemoteScheduler = func(clusterID uuid.UUID) deploy.Scheduler {
		return deploy.RemoteSwarm{Store: db, Box: box, ClusterID: clusterID, Timeout: 45 * time.Minute}
	}
	go worker.Run(ctx)
	go templates.RunRepositorySyncScheduler(ctx, db, box, nil, logger, worker.ID)
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
