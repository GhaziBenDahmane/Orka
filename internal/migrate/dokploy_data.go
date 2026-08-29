package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DokployDatabaseTransferManifest struct {
	Version     int                               `json:"version"`
	Connections []DokployDatabaseSourceConnection `json:"connections"`
}

type DokployDatabaseSourceConnection struct {
	SourceID string `json:"sourceId"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
	Version  string `json:"version,omitempty"`
}

type DokployDatabaseTransferReport struct {
	DryRun  bool                      `json:"dryRun"`
	Queued  int                       `json:"queued"`
	Planned int                       `json:"planned"`
	Items   []store.DatabaseMigration `json:"items"`
}

var migrationSourceHostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}[A-Za-z0-9]$|^[A-Za-z0-9]$`)

func ParseDokployDatabaseTransferManifest(data []byte) (DokployDatabaseTransferManifest, error) {
	var manifest DokployDatabaseTransferManifest
	if len(data) > 1<<20 {
		return manifest, errors.New("database transfer manifest exceeds 1 MiB")
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(data), 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, fmt.Errorf("decode database transfer manifest: %w", err)
	}
	if manifest.Version != 1 {
		return manifest, errors.New("database transfer manifest version must be 1")
	}
	if len(manifest.Connections) == 0 || len(manifest.Connections) > 1000 {
		return manifest, errors.New("database transfer manifest must contain between 1 and 1000 connections")
	}
	seen := map[string]bool{}
	for i := range manifest.Connections {
		item := &manifest.Connections[i]
		item.SourceID, item.Host, item.Username, item.Database, item.Version = strings.TrimSpace(item.SourceID), strings.TrimSpace(item.Host), strings.TrimSpace(item.Username), strings.TrimSpace(item.Database), strings.TrimSpace(item.Version)
		if item.SourceID == "" || len(item.SourceID) > 255 || seen[item.SourceID] {
			return manifest, fmt.Errorf("connection %d has an empty, duplicate, or oversized sourceId", i+1)
		}
		seen[item.SourceID] = true
		if !migrationSourceHostPattern.MatchString(item.Host) {
			return manifest, fmt.Errorf("connection %s has an invalid source host", item.SourceID)
		}
		if item.Port < 0 || item.Port > 65535 {
			return manifest, fmt.Errorf("connection %s has an invalid source port", item.SourceID)
		}
		if item.Password == "" || len(item.Username) > 255 || len(item.Password) > 64<<10 || len(item.Database) > 255 {
			return manifest, fmt.Errorf("connection %s requires a password and bounded username and database values", item.SourceID)
		}
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return manifest, errors.New("database transfer manifest must contain one JSON object")
	}
	return manifest, nil
}

func QueueDokployDatabaseTransfers(ctx context.Context, destination *store.Store, box *cryptox.Box, options DokployOptions, manifest DokployDatabaseTransferManifest) (DokployDatabaseTransferReport, error) {
	report := DokployDatabaseTransferReport{DryRun: options.DryRun, Items: []store.DatabaseMigration{}}
	if options.SourceURL == "" || options.SourceOrganizationID == "" || options.TargetOrganizationID == uuid.Nil {
		return report, errors.New("source URL, source organization, and target organization are required")
	}
	source, err := pgxpool.New(ctx, options.SourceURL)
	if err != nil {
		return report, fmt.Errorf("open Dokploy database: %w", err)
	}
	defer source.Close()
	if err = source.Ping(ctx); err != nil {
		return report, fmt.Errorf("connect to Dokploy database: %w", err)
	}
	databases, err := readDatabases(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	byID := make(map[string]sourceDatabase, len(databases))
	for _, item := range databases {
		byID[item.id] = item
	}
	registry := database.NewRegistry()
	for _, connection := range manifest.Connections {
		sourceDatabase, ok := byID[connection.SourceID]
		if !ok {
			return report, fmt.Errorf("Dokploy database %q does not belong to the source organization", connection.SourceID)
		}
		if !migrationBackupCapableEngine(sourceDatabase.engine) {
			return report, fmt.Errorf("database %s uses unsupported transfer engine %q", connection.SourceID, sourceDatabase.engine)
		}
		targetID := mappedID(options, "database:"+sourceDatabase.engine, sourceDatabase.id)
		target, targetErr := destination.GetDatabase(ctx, options.TargetOrganizationID, targetID)
		if targetErr != nil {
			return report, fmt.Errorf("target database for %s: %w; run the control-plane import first", connection.SourceID, targetErr)
		}
		if target.Engine != sourceDatabase.engine {
			return report, fmt.Errorf("database %s engine changed from %s to %s", connection.SourceID, sourceDatabase.engine, target.Engine)
		}
		sourceVersion := connection.Version
		if sourceVersion == "" {
			sourceVersion = imageVersion(sourceDatabase.dockerImage, target.Version)
		}
		credentials := map[string]string{"username": connection.Username, "password": connection.Password, "database": connection.Database}
		if connection.Port > 0 {
			credentials["port"] = fmt.Sprint(connection.Port)
		}
		extension, _ := registry.BackupExtension(sourceDatabase.engine)
		if _, planErr := registry.Backup(sourceDatabase.engine, sourceVersion, connection.Host, credentials, uuid.NewString()+"."+extension); planErr != nil {
			return report, fmt.Errorf("database %s source connection: %w", connection.SourceID, planErr)
		}
		migrationID := uuid.New()
		item := store.DatabaseMigration{ID: migrationID, DatabaseInstanceID: targetID, SourceKind: "dokploy", SourceID: connection.SourceID, SourceEngine: sourceDatabase.engine, SourceVersion: sourceVersion, SourceHost: connection.Host, Status: "planned"}
		if options.DryRun {
			report.Planned++
			report.Items = append(report.Items, item)
			continue
		}
		plain, _ := json.Marshal(database.SourceConnection{Username: connection.Username, Password: connection.Password, Database: connection.Database, Port: connection.Port})
		item.EncryptedSourceConfig, err = box.Encrypt(plain, "database-migration-source:"+migrationID.String())
		clear(plain)
		if err != nil {
			return report, err
		}
		item, err = destination.QueueDatabaseMigration(ctx, options.TargetOrganizationID, item)
		if errors.Is(err, store.ErrBusy) {
			return report, fmt.Errorf("database %s already has an active migration", connection.SourceID)
		}
		if err != nil {
			return report, err
		}
		report.Queued++
		report.Items = append(report.Items, item)
	}
	return report, nil
}
