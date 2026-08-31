package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

var errStorageNodeUnavailable = errors.New("storage node is not ready and active")

func (s *Server) rebindServiceStorageNode(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	service, volumes, ok := s.serviceNamedVolumes(w, r)
	if !ok {
		return
	}
	if len(volumes) == 0 {
		writeError(w, http.StatusBadRequest, "no_named_volumes", "service has no named volumes to relocate")
		return
	}
	var input struct {
		NodeID  string `json:"nodeId"`
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.NodeID = strings.TrimSpace(input.NodeID)
	if !store.ValidStorageNodeID(input.NodeID) {
		writeError(w, http.StatusBadRequest, "invalid_storage_node", "invalid Swarm storage node ID")
		return
	}
	if err = s.requireEligibleServiceStorageNode(r.Context(), service, input.NodeID); err != nil {
		if errors.Is(err, store.ErrInvalidStorageNode) {
			writeError(w, http.StatusBadRequest, "invalid_storage_node", err.Error())
			return
		}
		if errors.Is(err, errStorageNodeUnavailable) {
			writeError(w, http.StatusConflict, "storage_node_unavailable", err.Error())
			return
		}
		s.writeInternalError(w, r, http.StatusBadGateway, "storage_node_inventory_unavailable", "Swarm node inventory is unavailable", err)
		return
	}
	item, err := s.Store.RebindComposeServiceStorageNode(r.Context(), principal(r), serviceID, input.NodeID, input.Confirm, r.RemoteAddr)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrInvalidStorageNode):
			writeError(w, http.StatusBadRequest, "invalid_storage_node", err.Error())
		case errors.Is(err, store.ErrStorageNodeConfirmation):
			writeError(w, http.StatusBadRequest, "confirmation_mismatch", err.Error())
		case errors.Is(err, store.ErrStorageNodeUnassigned):
			writeError(w, http.StatusConflict, "storage_node_unassigned", err.Error())
		case errors.Is(err, store.ErrStorageNodeRebindRequiresStopped):
			writeError(w, http.StatusConflict, "service_must_be_stopped", err.Error())
		case errors.Is(err, store.ErrBusy):
			writeError(w, http.StatusConflict, "service_busy", "wait for active service and data operations before rebinding storage")
		default:
			writeStoreError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) requireEligibleServiceStorageNode(ctx context.Context, service store.ComposeService, nodeID string) error {
	var clusterID *uuid.UUID
	if err := s.Store.Pool.QueryRow(ctx, `SELECT cluster_id FROM environments WHERE id=$1`, service.EnvironmentID).Scan(&clusterID); err != nil {
		return err
	}
	var scheduler deploy.Scheduler = s.Swarm
	if clusterID != nil {
		scheduler = deploy.RemoteSwarm{Store: s.Store, Box: s.Box, ClusterID: *clusterID, Timeout: 30 * time.Second}
	}
	if scheduler == nil {
		return errors.New("swarm scheduler is not configured")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	nodes, err := scheduler.Nodes(checkCtx)
	if err != nil {
		return err
	}
	return validateStorageNodeTarget(nodes, nodeID)
}

func validateStorageNodeTarget(nodes []deploy.Node, nodeID string) error {
	if !store.ValidStorageNodeID(nodeID) {
		return store.ErrInvalidStorageNode
	}
	for _, node := range nodes {
		if node.ID != nodeID {
			continue
		}
		if !strings.EqualFold(node.Status, "ready") || !strings.EqualFold(node.Availability, "active") {
			return fmt.Errorf("%w: node %q is %s/%s", errStorageNodeUnavailable, nodeID, node.Status, node.Availability)
		}
		return nil
	}
	return fmt.Errorf("%w: node %q does not belong to the service cluster", store.ErrInvalidStorageNode, nodeID)
}
