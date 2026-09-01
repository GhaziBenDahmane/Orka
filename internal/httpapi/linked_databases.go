package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/deploy"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

var linkedDatabaseServiceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

type linkedDatabaseInput struct {
	Name                  string `json:"name"`
	Engine                string `json:"engine"`
	Version               string `json:"version"`
	ConnectionServiceName string `json:"connectionServiceName"`
	Database              string `json:"database"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	Port                  int    `json:"port"`
}

func (s *Server) createLinkedDatabase(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	var in linkedDatabaseInput
	if !decode(w, r, &in) {
		return
	}
	in.Name, err = normalizeResourceName(in.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_name", err.Error())
		return
	}
	p := principal(r)
	service, _, err := s.Store.GetComposeService(r.Context(), p.OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	databaseID := uuid.New()
	item, credentials, err := s.prepareLinkedDatabase(service, databaseID, in)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_compose_database", err.Error())
		return
	}
	encoded, _ := json.Marshal(credentials)
	encrypted, err := s.Box.Encrypt(encoded, cryptox.ResourceContext("database-credentials", databaseID.String()))
	if err != nil {
		s.writeInternalError(w, r, http.StatusInternalServerError, "encryption_failed", "database credentials could not be encrypted", err)
		return
	}
	item, err = s.Store.CreateLinkedDatabaseWithAudit(r.Context(), p, serviceID, service.Revision, item, encrypted, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) rotateLinkedDatabaseCredentials(w http.ResponseWriter, r *http.Request) {
	databaseID, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid database id")
		return
	}
	var in linkedDatabaseInput
	if !decode(w, r, &in) {
		return
	}
	p := principal(r)
	current, err := s.Store.GetDatabase(r.Context(), p.OrganizationID, databaseID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if current.ManagementKind != "compose" {
		writeError(w, http.StatusConflict, "compose_database_required", store.ErrLinkedDatabaseRequired.Error())
		return
	}
	service, _, err := s.Store.GetComposeService(r.Context(), p.OrganizationID, current.ComposeServiceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	in.Name, in.Engine = current.Name, current.Engine
	item, credentials, err := s.prepareLinkedDatabase(service, databaseID, in)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_compose_database", err.Error())
		return
	}
	encoded, _ := json.Marshal(credentials)
	encrypted, err := s.Box.Encrypt(encoded, cryptox.ResourceContext("database-credentials", databaseID.String()))
	if err != nil {
		s.writeInternalError(w, r, http.StatusInternalServerError, "encryption_failed", "database credentials could not be encrypted", err)
		return
	}
	item, err = s.Store.RotateLinkedDatabaseCredentialsWithAudit(r.Context(), p, databaseID, service.Revision, item.ConnectionServiceName, item.Version, item.DriverSource, item.DriverDigest, item.Config, encrypted, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "database_busy", "wait for active database operations before rotating credentials")
			return
		}
		if errors.Is(err, store.ErrLinkedDatabaseRequired) {
			writeError(w, http.StatusConflict, "compose_database_required", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) unlinkDatabase(w http.ResponseWriter, r *http.Request) {
	databaseID, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid database id")
		return
	}
	if err = s.Store.QueueLinkedDatabaseUnlinkWithAudit(r.Context(), principal(r), databaseID, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrLinkedDatabaseRequired) {
			writeError(w, http.StatusConflict, "compose_database_required", err.Error())
			return
		}
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "database_busy", "cancel or wait for active database operations before unlinking")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "unlink_queued"})
}

func (s *Server) prepareLinkedDatabase(service store.ComposeService, databaseID uuid.UUID, in linkedDatabaseInput) (store.DatabaseInstance, map[string]string, error) {
	if s.Databases == nil {
		return store.DatabaseInstance{}, nil, errors.New("database registry is not configured")
	}
	in.Engine = strings.ToLower(strings.TrimSpace(in.Engine))
	driver, found := s.Databases.Engine(in.Engine)
	if !found || !driver.BackupCapable {
		return store.DatabaseInstance{}, nil, errors.New("database engine does not support backup and restore")
	}
	in.ConnectionServiceName = strings.TrimSpace(in.ConnectionServiceName)
	if !linkedDatabaseServiceName.MatchString(in.ConnectionServiceName) {
		return store.DatabaseInstance{}, nil, errors.New("connection service name must use 1-63 lowercase letters, digits, underscores, or hyphens")
	}
	if _, err := deploy.ComposeServiceImage(service.ComposeYAML, in.ConnectionServiceName); err != nil {
		return store.DatabaseInstance{}, nil, err
	}
	if in.Version == "" {
		in.Version = driver.DefaultVersion
	}
	credentials := map[string]string{
		"database": strings.TrimSpace(in.Database),
		"username": strings.TrimSpace(in.Username),
		"password": in.Password,
	}
	for key, value := range credentials {
		if len(value) > 8192 {
			return store.DatabaseInstance{}, nil, fmt.Errorf("database credential %q exceeds 8192 bytes", key)
		}
	}
	if in.Port != 0 {
		credentials["port"] = strconv.Itoa(in.Port)
	}
	filename := databaseID.String() + "." + driver.BackupExtension
	if _, err := s.Databases.Backup(in.Engine, in.Version, in.ConnectionServiceName, credentials, filename); err != nil {
		return store.DatabaseInstance{}, nil, err
	}
	if _, err := s.Databases.Restore(in.Engine, in.Version, in.ConnectionServiceName, credentials, filename); err != nil {
		return store.DatabaseInstance{}, nil, err
	}
	return store.DatabaseInstance{
		ID: databaseID, Name: in.Name, Slug: slugify(in.Name), Engine: in.Engine, Version: in.Version,
		DriverSource: driver.Source, DriverDigest: driver.ArtifactDigest, ManagementKind: "compose",
		ConnectionServiceName: in.ConnectionServiceName,
		Config:                map[string]any{"database": credentials["database"], "username": credentials["username"], "port": in.Port},
	}, credentials, nil
}
