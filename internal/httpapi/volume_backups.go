package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func (s *Server) listServiceVolumes(w http.ResponseWriter, r *http.Request) {
	service, volumes, ok := s.serviceNamedVolumes(w, r)
	if !ok {
		return
	}
	items := make([]map[string]any, 0, len(volumes))
	for _, name := range volumes {
		actual, err := deploy.StackVolumeName(service.StackName, name)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid_compose", err.Error())
			return
		}
		items = append(items, map[string]any{"name": name, "dockerName": actual, "storageNodeId": service.StorageNodeID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) listVolumeBackupPolicies(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	items, err := s.Store.ListVolumeBackupPolicies(r.Context(), principal(r).OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) putVolumeBackupPolicy(w http.ResponseWriter, r *http.Request) {
	service, volumes, ok := s.serviceNamedVolumes(w, r)
	if !ok {
		return
	}
	volumeName := r.PathValue("volumeName")
	if !hasVolume(volumes, volumeName) {
		writeError(w, http.StatusBadRequest, "unknown_volume", "volume is not a named volume mounted by this service")
		return
	}
	var in struct {
		DestinationID   uuid.UUID `json:"destinationId"`
		IntervalSeconds int       `json:"intervalSeconds"`
		RetentionCount  int       `json:"retentionCount"`
		Quiesce         bool      `json:"quiesce"`
		Enabled         bool      `json:"enabled"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.DestinationID == uuid.Nil || in.IntervalSeconds < 900 || in.IntervalSeconds > 2678400 || in.RetentionCount < 1 || in.RetentionCount > 100 {
		writeError(w, http.StatusBadRequest, "invalid_volume_backup_policy", "destinationId is required, intervalSeconds must be 900..2678400, and retentionCount must be 1..100")
		return
	}
	nodeID := service.StorageNodeID
	if nodeID == "" {
		var err error
		nodeID, err = s.resolveServiceVolumeNode(r.Context(), service, volumeName)
		if err != nil {
			s.writeInternalError(w, r, http.StatusConflict, "volume_node_unavailable", "the volume storage node could not be resolved; deploy the service and retry", err)
			return
		}
	}
	p := principal(r)
	item, err := s.Store.UpsertVolumeBackupPolicyWithAudit(r.Context(), p, service.ID, volumeName, nodeID, in.DestinationID, in.IntervalSeconds, in.RetentionCount, in.Quiesce, in.Enabled, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrStorageNodeMismatch) {
			writeError(w, http.StatusConflict, "storage_node_mismatch", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteVolumeBackupPolicy(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	volumeName := r.PathValue("volumeName")
	p := principal(r)
	if err = s.Store.DeleteVolumeBackupPolicyWithAudit(r.Context(), p, serviceID, volumeName, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "volume_backup_policy_busy", "wait for active backups and restores to finish before deleting the policy")
			return
		}
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listVolumeBackups(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	items, err := s.Store.ListVolumeBackups(r.Context(), principal(r).OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createVolumeBackup(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	p := principal(r)
	item, err := s.Store.QueueVolumeBackupWithAudit(r.Context(), p, serviceID, r.PathValue("volumeName"), r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "backup_in_progress", "wait for the active volume backup to finish before starting another")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) listVolumeRestores(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	items, err := s.Store.ListVolumeRestores(r.Context(), principal(r).OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getVolumeBackup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("backupID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid volume backup id")
		return
	}
	item, err := s.Store.GetVolumeBackup(r.Context(), principal(r).OrganizationID, id, false)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) cancelVolumeBackup(w http.ResponseWriter, r *http.Request) {
	s.cancelVolumeOperation(w, r, "backupID", s.Store.CancelVolumeBackupWithAudit)
}

func (s *Server) restoreVolumeBackup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("backupID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid volume backup id")
		return
	}
	var in struct {
		Confirm string `json:"confirm"`
		Offline bool   `json:"offline"`
	}
	if !decode(w, r, &in) {
		return
	}
	p := principal(r)
	var item store.VolumeRestore
	if in.Offline {
		item, err = s.Store.QueueOfflineVolumeRestoreWithAudit(r.Context(), p, id, in.Confirm, r.RemoteAddr)
	} else {
		item, err = s.Store.QueueVolumeRestoreWithAudit(r.Context(), p, id, in.Confirm, r.RemoteAddr)
	}
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "restore_in_progress", "wait for the active volume restore to finish before starting another")
			return
		}
		if errors.Is(err, store.ErrOfflineRestoreRequiresStopped) {
			writeError(w, http.StatusConflict, "offline_restore_requires_stopped_service", err.Error())
			return
		}
		if errors.Is(err, store.ErrStorageNodeUnassigned) {
			writeError(w, http.StatusConflict, "storage_node_unassigned", err.Error())
			return
		}
		if errors.Is(err, store.ErrBackupNotRestorable) || strings.Contains(err.Error(), "confirmation") {
			writeError(w, http.StatusConflict, "restore_rejected", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) getVolumeRestore(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("restoreID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid volume restore id")
		return
	}
	item, err := s.Store.GetVolumeRestore(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) cancelVolumeRestore(w http.ResponseWriter, r *http.Request) {
	s.cancelVolumeOperation(w, r, "restoreID", s.Store.CancelVolumeRestoreWithAudit)
}

func (s *Server) cancelVolumeOperation(w http.ResponseWriter, r *http.Request, pathKey string, cancel func(context.Context, store.Principal, uuid.UUID, string) error) {
	id, err := uuid.Parse(r.PathValue(pathKey))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid volume operation id")
		return
	}
	p := principal(r)
	if err = cancel(r.Context(), p, id, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrNotCancellable) {
			writeError(w, http.StatusConflict, "not_cancellable", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "cancellation_requested"})
}

func (s *Server) serviceNamedVolumes(w http.ResponseWriter, r *http.Request) (store.ComposeService, []string, bool) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return store.ComposeService{}, nil, false
	}
	service, _, err := s.Store.GetComposeService(r.Context(), principal(r).OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return store.ComposeService{}, nil, false
	}
	volumes, err := deploy.NamedVolumes(service.ComposeYAML)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_compose", err.Error())
		return store.ComposeService{}, nil, false
	}
	return service, volumes, true
}

func (s *Server) resolveServiceVolumeNode(ctx context.Context, service store.ComposeService, volumeName string) (string, error) {
	var clusterID *uuid.UUID
	var deployed bool
	if err := s.Store.Pool.QueryRow(ctx, `SELECT environment.cluster_id,EXISTS(SELECT 1 FROM deployments deployment WHERE deployment.compose_service_id=$2 AND deployment.status='succeeded') FROM environments environment WHERE environment.id=$1`, service.EnvironmentID, service.ID).Scan(&clusterID, &deployed); err != nil {
		return "", err
	}
	var scheduler deploy.Scheduler = s.Swarm
	if clusterID != nil {
		scheduler = deploy.RemoteSwarm{Store: s.Store, Box: s.Box, ClusterID: *clusterID, Timeout: 30 * time.Second}
	}
	if scheduler == nil {
		return "", errors.New("swarm scheduler is not configured")
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if deployed {
		resolver, ok := scheduler.(deploy.VolumeNodeResolver)
		if !ok {
			return "", errors.New("scheduler does not support volume placement discovery")
		}
		actual, err := deploy.StackVolumeName(service.StackName, volumeName)
		if err != nil {
			return "", err
		}
		return resolver.ResolveVolumeNode(resolveCtx, service.StackName, actual)
	}
	resolver, ok := scheduler.(deploy.StorageNodeResolver)
	if !ok {
		return "", errors.New("scheduler does not support storage placement")
	}
	return resolver.ResolveStorageNode(resolveCtx, service.StackName)
}

func hasVolume(volumes []string, wanted string) bool {
	for _, volume := range volumes {
		if volume == wanted {
			return true
		}
	}
	return false
}
