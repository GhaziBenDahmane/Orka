package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bendahma/dokploy-go/internal/config"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/httpapi"
	dockyardmigrate "github.com/bendahma/dokploy-go/internal/migrate"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/bendahma/dokploy-go/internal/templates"
	"github.com/google/uuid"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dockyard <serve|import-dokploy-templates|validate-dokploy-templates|migrate-dokploy>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve()
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
		fmt.Fprintln(os.Stderr, "usage: dockyard <serve|import-dokploy-templates|validate-dokploy-templates|migrate-dokploy>")
		os.Exit(2)
	}
	if err != nil {
		slog.Error("dockyard stopped", "error", err)
		os.Exit(1)
	}
}

func migrateDokploy(arguments []string) error {
	flags := flag.NewFlagSet("migrate-dokploy", flag.ContinueOnError)
	sourceURL := flags.String("source-url", "", "Dokploy PostgreSQL connection URL")
	sourceOrganization := flags.String("source-organization", "", "Dokploy organization ID")
	targetOrganization := flags.String("target-organization", "", "Dockyard organization UUID")
	dryRun := flags.Bool("dry-run", true, "validate and report without writing")
	keyFile := flags.String("encryption-key-file", "", "Dokploy exportEncryptionKeys file")
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
	report, err := dockyardmigrate.ImportDokploy(ctx, db, box, deploy.Compiler{PublicNetwork: cfg.TraefikNetwork, AllowUnsafe: cfg.UnsafeWorkloads}, dockyardmigrate.DokployOptions{SourceURL: *sourceURL, SourceOrganizationID: *sourceOrganization, TargetOrganizationID: targetID, DryRun: *dryRun, EncryptionKeys: keys})
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
	worker := &deploy.Worker{Store: db, Box: box, Compiler: compiler, Swarm: swarm, Concurrency: cfg.WorkerConcurrency, Logger: logger, ID: uuid.NewString(), Databases: databaseRegistry, BackupDirectory: cfg.BackupDirectory, Builder: deploy.Builder{GitBin: "git", DockerBin: cfg.DockerBin}}
	go worker.Run(ctx)
	api := &httpapi.Server{Store: db, Box: box, Compiler: compiler, Databases: databaseRegistry, Swarm: swarm, SessionTTL: cfg.SessionTTL, Logger: logger, PublicURL: cfg.PublicURL}
	httpServer := &http.Server{Addr: cfg.ListenAddr, Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	logger.Info("dockyard listening", "address", cfg.ListenAddr)
	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
