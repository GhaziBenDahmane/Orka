package httpapi

import (
	"net/http"
	"strings"

	"github.com/GhaziBenDahmane/Orka/internal/deploy"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func (s *Server) listManagedNetworks(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListManagedNetworks(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getManagedNetwork(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("networkID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid network id")
		return
	}
	item, err := s.Store.GetManagedNetwork(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createManagedNetwork(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name       string                    `json:"name"`
		Driver     string                    `json:"driver"`
		ClusterID  *uuid.UUID                `json:"clusterId"`
		Internal   bool                      `json:"internal"`
		Attachable *bool                     `json:"attachable"`
		EnableIPv4 *bool                     `json:"enableIpv4"`
		EnableIPv6 bool                      `json:"enableIpv6"`
		MTU        *int                      `json:"mtu"`
		IPAM       []store.NetworkIPAMConfig `json:"ipam"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.Name, input.Driver = strings.TrimSpace(input.Name), strings.ToLower(strings.TrimSpace(input.Driver))
	if input.Driver == "" {
		input.Driver = "overlay"
	}
	attachable, enableIPv4 := true, true
	if input.Attachable != nil {
		attachable = *input.Attachable
	}
	if input.EnableIPv4 != nil {
		enableIPv4 = *input.EnableIPv4
	}
	spec := deploy.ManagedNetworkSpec{ID: uuid.NewString(), Name: input.Name, Driver: input.Driver, Internal: input.Internal, Attachable: attachable, EnableIPv4: enableIPv4, EnableIPv6: input.EnableIPv6, MTU: input.MTU}
	for _, config := range input.IPAM {
		spec.IPAM = append(spec.IPAM, deploy.NetworkIPAMConfig{Subnet: config.Subnet, Gateway: config.Gateway, IPRange: config.IPRange})
	}
	if err := deploy.ValidateManagedNetworkSpec(spec); err != nil || input.Name == s.Compiler.PublicNetwork {
		if err == nil {
			err = errManagedNetworkReserved
		}
		writeError(w, http.StatusBadRequest, "invalid_network", err.Error())
		return
	}
	p := principal(r)
	item, err := s.Store.CreateManagedNetworkWithAudit(r.Context(), p, store.ManagedNetwork{ClusterID: input.ClusterID, Name: input.Name, Driver: input.Driver, Internal: input.Internal, Attachable: attachable, EnableIPv4: enableIPv4, EnableIPv6: input.EnableIPv6, MTU: input.MTU, IPAM: input.IPAM}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

var errManagedNetworkReserved = &managedNetworkValidationError{}

type managedNetworkValidationError struct{}

func (*managedNetworkValidationError) Error() string {
	return "network name is reserved by the platform"
}

func (s *Server) deleteManagedNetwork(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("networkID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid network id")
		return
	}
	p := principal(r)
	if err = s.Store.QueueManagedNetworkDeletionWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) retryManagedNetwork(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("networkID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid network id")
		return
	}
	p := principal(r)
	item, err := s.Store.RetryManagedNetworkProvisioningWithAudit(r.Context(), p, id, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) listServiceNetworks(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	items, err := s.Store.ListServiceNetworks(r.Context(), principal(r).OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) replaceServiceNetworks(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	var input struct {
		NetworkIDs []uuid.UUID `json:"networkIds"`
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.NetworkIDs) > 16 || hasDuplicateUUIDs(input.NetworkIDs) {
		writeError(w, http.StatusBadRequest, "invalid_networks", "a service may have at most 16 unique network ids")
		return
	}
	p := principal(r)
	service, routes, err := s.Store.GetComposeService(r.Context(), p.OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	catalog, err := s.Store.ListManagedNetworks(r.Context(), p.OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	wanted := make(map[uuid.UUID]bool, len(input.NetworkIDs))
	for _, id := range input.NetworkIDs {
		wanted[id] = true
	}
	names := []string{}
	for _, network := range catalog {
		if wanted[network.ID] {
			names = append(names, network.Name)
		}
	}
	if len(names) == len(input.NetworkIDs) {
		if _, compileErr := s.Compiler.CompileWithManagedNetworks(service.ComposeYAML, routes, names); compileErr != nil {
			writeError(w, http.StatusBadRequest, "invalid_networks", compileErr.Error())
			return
		}
	}
	items, err := s.Store.ReplaceServiceNetworksWithAudit(r.Context(), p, serviceID, input.NetworkIDs, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func hasDuplicateUUIDs(items []uuid.UUID) bool {
	seen := make(map[uuid.UUID]bool, len(items))
	for _, id := range items {
		if id == uuid.Nil || seen[id] {
			return true
		}
		seen[id] = true
	}
	return false
}
