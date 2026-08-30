package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
	"github.com/bendahma/dokploy-go/internal/netpolicy"
	"github.com/bendahma/dokploy-go/internal/observability"
	"github.com/bendahma/dokploy-go/internal/releaseevidence"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/bendahma/dokploy-go/internal/templates"
	"github.com/bendahma/dokploy-go/internal/volumeartifact"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, dockyardUsage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve()
	case "agent":
		err = runAgent()
	case "ai-auditor":
		err = runAIAuditor(os.Args[2:])
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
	case "rotate-master-key":
		err = rotateMasterKey(os.Args[2:])
	case "validate-production-certification":
		err = validateProductionCertification(os.Args[2:])
	case "validate-egress-policy":
		err = validateEgressPolicy(os.Args[2:])
	case "validate-database-url":
		err = validateDatabaseURL(os.Args[2:], os.Stdin)
	case "validate-agent-endpoints":
		err = validateAgentEndpoints(os.Args[2:])
	case "volume-artifact":
		err = runVolumeArtifact(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, dockyardUsage)
		os.Exit(2)
	}
	if err != nil {
		slog.Error("dockyard stopped", "error", err)
		os.Exit(1)
	}
}

const dockyardUsage = "usage: dockyard <serve|agent|ai-auditor|import-dokploy-templates|validate-dokploy-templates|sign-template-catalog|migrate-dokploy|migrate-dokploy-data|verify-dokploy-import|rotate-master-key|validate-production-certification|validate-egress-policy|validate-database-url|validate-agent-endpoints|volume-artifact>"

func validateEgressPolicy(arguments []string) error {
	flags := flag.NewFlagSet("validate-egress-policy", flag.ContinueOnError)
	cidrs := flags.String("cidrs", "", "comma-separated private egress CIDRs")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: dockyard validate-egress-policy [--cidrs CIDR,...]")
	}
	_, err := netpolicy.ParseAllowedCIDRs(*cidrs)
	if err != nil {
		return fmt.Errorf("validate egress policy: %w", err)
	}
	return nil
}

func validateDatabaseURL(arguments []string, input io.Reader) error {
	flags := flag.NewFlagSet("validate-database-url", flag.ContinueOnError)
	requireTLS := flags.Bool("require-tls", false, "require sslmode=verify-full")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: dockyard validate-database-url [--require-tls] < URL_FILE")
	}
	data, err := io.ReadAll(io.LimitReader(input, 65537))
	if err != nil {
		return fmt.Errorf("read database URL: %w", err)
	}
	if len(data) > 65536 {
		return errors.New("database URL exceeds 65536 bytes")
	}
	return config.ValidateDatabaseURL(strings.TrimSpace(string(data)), *requireTLS)
}

func validateAgentEndpoints(arguments []string) error {
	flags := flag.NewFlagSet("validate-agent-endpoints", flag.ContinueOnError)
	controlPlaneURL := flags.String("control-plane-url", "", "public HTTPS control-plane origin")
	agentURL := flags.String("agent-url", "", "public HTTPS agent mTLS origin")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *controlPlaneURL == "" || *agentURL == "" {
		return errors.New("usage: dockyard validate-agent-endpoints --control-plane-url URL --agent-url URL")
	}
	return agent.ValidateEndpoints(*controlPlaneURL, *agentURL)
}

func validateProductionCertification(arguments []string) error {
	flags := flag.NewFlagSet("validate-production-certification", flag.ContinueOnError)
	path := flags.String("file", "", "path to production certification JSON")
	sourceCommit := flags.String("source-commit", "", "expected 40-character source commit")
	candidateImage := flags.String("candidate-image", "", "expected immutable GHCR candidate image")
	validationTime := flags.String("at", "", "validation time in RFC3339 (defaults to now)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" || *sourceCommit == "" || *candidateImage == "" {
		return errors.New("usage: dockyard validate-production-certification --file PATH --source-commit SHA --candidate-image GHCR_DIGEST")
	}
	file, err := os.Open(*path)
	if err != nil {
		return fmt.Errorf("open production certification: %w", err)
	}
	defer file.Close()
	certification, err := releaseevidence.DecodeProductionCertification(file)
	if err != nil {
		return err
	}
	now := time.Now()
	if *validationTime != "" {
		now, err = time.Parse(time.RFC3339, *validationTime)
		if err != nil {
			return errors.New("--at must be an RFC3339 timestamp")
		}
	}
	if err = certification.Validate(*sourceCommit, *candidateImage, now); err != nil {
		return fmt.Errorf("validate production certification: %w", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(certification)
}

func runVolumeArtifact(arguments []string) error {
	flags := flag.NewFlagSet("volume-artifact", flag.ContinueOnError)
	jobFile := flags.String("job-file", "", "path to the mode-0400 volume artifact job secret")
	volumeRoot := flags.String("volume-root", "/volume", "mounted volume root")
	workRoot := flags.String("work-root", "/tmp", "temporary encrypted artifact workspace")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *jobFile == "" || !filepath.IsAbs(*volumeRoot) || !filepath.IsAbs(*workRoot) {
		return errors.New("usage: dockyard volume-artifact --job-file PATH [--volume-root /volume --work-root /tmp]")
	}
	job, err := volumeartifact.ReadJob(*jobFile)
	if err != nil {
		return fmt.Errorf("read volume artifact job: %w", err)
	}
	result, err := volumeartifact.Run(context.Background(), job, *volumeRoot, *workRoot)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func rotateMasterKey(arguments []string) error {
	flags := flag.NewFlagSet("rotate-master-key", flag.ContinueOnError)
	databaseURL := flags.String("database-url", "", "PostgreSQL connection URL (or DOCKYARD_DATABASE_URL/DOCKYARD_DATABASE_URL_FILE)")
	oldKeyFile := flags.String("old-key-file", "", "mode-0600 file containing the current base64 master key")
	newKeyFile := flags.String("new-key-file", "", "mode-0600 file containing the new base64 master key")
	dryRun := flags.Bool("dry-run", true, "authenticate all records and report without changing them")
	confirm := flags.String("confirm", "", "new-key fingerprint required when --dry-run=false")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *oldKeyFile == "" || *newKeyFile == "" {
		return errors.New("usage: dockyard rotate-master-key --old-key-file PATH --new-key-file PATH [--database-url URL] [--dry-run=false --confirm NEW_KEY_FINGERPRINT]")
	}
	resolvedDatabaseURL, err := resolveDatabaseURL(*databaseURL)
	if err != nil {
		return err
	}
	oldKey, err := readRestrictedMasterKey(*oldKeyFile)
	if err != nil {
		return fmt.Errorf("read old master key: %w", err)
	}
	defer clear(oldKey)
	newKey, err := readRestrictedMasterKey(*newKeyFile)
	if err != nil {
		return fmt.Errorf("read new master key: %w", err)
	}
	defer clear(newKey)
	newFingerprint := store.MasterKeyFingerprint(newKey)
	if !*dryRun && *confirm != newFingerprint {
		return fmt.Errorf("--confirm must exactly match the new key fingerprint %q; run the default dry-run first", newFingerprint)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, resolvedDatabaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	report, err := store.RotateMasterKey(ctx, pool, oldKey, newKey, *dryRun)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}

func resolveDatabaseURL(flagValue string) (string, error) {
	if strings.TrimSpace(flagValue) != "" {
		return strings.TrimSpace(flagValue), nil
	}
	value, path := os.Getenv("DOCKYARD_DATABASE_URL"), os.Getenv("DOCKYARD_DATABASE_URL_FILE")
	if value != "" && path != "" {
		return "", errors.New("DOCKYARD_DATABASE_URL and DOCKYARD_DATABASE_URL_FILE cannot both be configured")
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read DOCKYARD_DATABASE_URL_FILE: %w", err)
		}
		defer clear(data)
		value = string(data)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("--database-url or DOCKYARD_DATABASE_URL/DOCKYARD_DATABASE_URL_FILE is required")
	}
	return value, nil
}

func readRestrictedMasterKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("key file must be a regular file with no group or other permissions")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, openedInfo) {
		return nil, errors.New("key file changed while it was being opened")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	if len(encoded) > 1024 {
		return nil, errors.New("key file exceeds 1 KiB")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, errors.New("key file must contain one base64-encoded 32-byte key")
	}
	return key, nil
}

func runAgent() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	allowedEgress, err := netpolicy.ParseAllowedCIDRs(os.Getenv("DOCKYARD_EGRESS_PRIVATE_CIDRS"))
	if err != nil {
		return fmt.Errorf("DOCKYARD_EGRESS_PRIVATE_CIDRS: %w", err)
	}
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
		EgressPolicy:        &netpolicy.Policy{Allowed: allowedEgress},
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
	box, err := cryptox.New(cfg.MasterKey)
	if err != nil {
		return err
	}
	var db *store.Store
	if *dryRun {
		db, err = store.OpenReadOnlyVerified(ctx, cfg.DatabaseURL, box)
	} else {
		db, err = store.OpenVerified(ctx, cfg.DatabaseURL, box)
	}
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	db.RequireRemoteBackups = cfg.RequireRemoteBackups
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
	box, err := cryptox.New(cfg.MasterKey)
	if err != nil {
		return err
	}
	var db *store.Store
	if *dryRun {
		db, err = store.OpenReadOnlyVerified(ctx, cfg.DatabaseURL, box)
	} else {
		db, err = store.OpenVerified(ctx, cfg.DatabaseURL, box)
	}
	if err != nil {
		return err
	}
	defer db.Pool.Close()
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
	box, err := cryptox.New(cfg.MasterKey)
	if err != nil {
		return err
	}
	db, err := store.OpenVerified(ctx, cfg.DatabaseURL, box)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	db.RequireRemoteBackups = cfg.RequireRemoteBackups
	compiler := deploy.Compiler{PublicNetwork: cfg.TraefikNetwork, AllowUnsafe: cfg.UnsafeWorkloads}
	if report, seedErr := templates.SeedBuiltinCatalog(ctx, db, compiler); seedErr != nil {
		return fmt.Errorf("seed built-in template catalog: %w", seedErr)
	} else {
		logger.Info("built-in template catalog ready", "templates", report.Imported)
	}
	if err = db.ValidateBackupConfiguration(ctx); err != nil {
		return fmt.Errorf("validate backup configuration: %w", err)
	}
	swarm := deploy.Swarm{DockerBin: cfg.DockerBin, Network: cfg.TraefikNetwork, Timeout: 5 * time.Minute, ServiceName: cfg.SwarmServiceName}
	databaseRegistry := database.NewRegistry()
	if cfg.DatabaseDriverDirectory != "" {
		if err := databaseRegistry.LoadExternal(cfg.DatabaseDriverDirectory); err != nil {
			return fmt.Errorf("load external database drivers: %w", err)
		}
	}
	metrics := observability.NewMetrics()
	driverMetrics := make([]observability.DatabaseDriverInfo, 0, len(databaseRegistry.Engines()))
	for _, engine := range databaseRegistry.Engines() {
		driverMetrics = append(driverMetrics, observability.DatabaseDriverInfo{Engine: engine.Name, Source: engine.Source, Digest: engine.ArtifactDigest, BackupCapable: engine.BackupCapable})
	}
	metrics.SetDatabaseDrivers(driverMetrics)
	metrics.SetCertificateExpiry("agent_ca", cfg.AgentCAExpiresAt)
	metrics.SetCertificateExpiry("agent_previous_ca", cfg.AgentPreviousCAExpiresAt)
	metrics.SetCertificateExpiry("agent_server", cfg.AgentServerCertExpiresAt)
	egressPolicy := &netpolicy.Policy{Allowed: cfg.EgressPrivateCIDRs}
	egressTransport := egressPolicy.Transport()
	notificationClient := &http.Client{Transport: egressTransport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("notification redirects are disabled") }}
	worker := &deploy.Worker{Store: db, Box: box, Compiler: compiler, Swarm: swarm, Concurrency: cfg.WorkerConcurrency, Logger: logger, ID: uuid.NewString(), Databases: databaseRegistry, BackupDirectory: cfg.BackupDirectory, Builder: deploy.Builder{GitBin: "git", DockerBin: cfg.DockerBin, EgressPolicy: egressPolicy, MaxWorkspaceBytes: cfg.MaxBuildWorkspaceBytes}, Metrics: metrics, NotificationClient: notificationClient, EgressPolicy: egressPolicy, EgressTransport: egressTransport}
	worker.RemoteScheduler = func(clusterID uuid.UUID) deploy.Scheduler {
		return deploy.RemoteSwarm{Store: db, Box: box, ClusterID: clusterID, Timeout: 45 * time.Minute}
	}
	go worker.Run(ctx)
	go templates.RunRepositorySyncScheduler(ctx, db, box, &http.Client{Transport: egressTransport, Timeout: 45 * time.Second}, logger, worker.ID)
	api := &httpapi.Server{Store: db, Box: box, Compiler: compiler, Databases: databaseRegistry, Swarm: swarm, SessionTTL: cfg.SessionTTL, Logger: logger, PublicURL: cfg.PublicURL, OIDCHTTPClient: &http.Client{Transport: egressTransport, Timeout: 15 * time.Second}, EgressTransport: egressTransport, Metrics: metrics, MetricsTokenHash: cryptox.Digest(cfg.MetricsToken), AgentCACertificate: cfg.AgentCACertificate, AgentPreviousCACertificate: cfg.AgentPreviousCACertificate, AgentCATrustBundle: cfg.AgentCATrustBundle, AgentCAKey: cfg.AgentCAKey, AgentCertificateTTL: cfg.AgentCertificateTTL, TrustedProxyCIDRs: cfg.TrustedProxyCIDRs}
	httpServer := newPlatformHTTPServer(cfg.ListenAddr, api.Handler(), 30*time.Second)
	servers := []*http.Server{httpServer}
	var agentServer *http.Server
	if cfg.AgentListenAddr != "" {
		clientCAs, tlsErr := httpapi.AgentTLSConfig(cfg.AgentCATrustBundle)
		if tlsErr != nil {
			return tlsErr
		}
		agentServer = newPlatformHTTPServer(cfg.AgentListenAddr, api.AgentHandler(), 35*time.Second)
		agentServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
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

func newPlatformHTTPServer(address string, handler http.Handler, requestTimeout time.Duration) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       requestTimeout,
		WriteTimeout:      requestTimeout,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
}
