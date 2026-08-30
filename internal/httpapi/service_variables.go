package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"unicode/utf8"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

const (
	maxServiceVariables       = 256
	maxServiceVariableName    = 128
	maxServiceVariableValue   = 64 << 10
	maxServiceEnvironmentJSON = 1 << 20
)

var serviceVariableNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type serviceVariableItem struct {
	Name string `json:"name"`
}

type serviceVariableList struct {
	Items    []serviceVariableItem `json:"items"`
	Revision int64                 `json:"revision"`
}

func validateServiceVariable(name, value string) error {
	if len(name) == 0 || len(name) > maxServiceVariableName || !serviceVariableNamePattern.MatchString(name) {
		return errors.New("variable names must match [A-Za-z_][A-Za-z0-9_]* and contain at most 128 bytes")
	}
	if len(value) > maxServiceVariableValue || !utf8.ValidString(value) || containsNUL(value) {
		return errors.New("variable values must be valid UTF-8 without NUL bytes and contain at most 65536 bytes")
	}
	return nil
}

func validateServiceVariables(values map[string]string) error {
	if len(values) > maxServiceVariables {
		return errors.New("a service may contain at most 256 variables")
	}
	for name, value := range values {
		if err := validateServiceVariable(name, value); err != nil {
			return err
		}
	}
	plain, err := json.Marshal(values)
	if err != nil || len(plain) > maxServiceEnvironmentJSON {
		return errors.New("the combined service environment exceeds 1 MiB")
	}
	return nil
}

func containsNUL(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == 0 {
			return true
		}
	}
	return false
}

func serviceVariableResponse(values map[string]string, revision int64) serviceVariableList {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	items := make([]serviceVariableItem, 0, len(names))
	for _, name := range names {
		items = append(items, serviceVariableItem{Name: name})
	}
	return serviceVariableList{Items: items, Revision: revision}
}

func (s *Server) decryptServiceVariables(item store.ComposeService) (map[string]string, error) {
	if item.EncryptedEnv == "" {
		return map[string]string{}, nil
	}
	plain, err := s.Box.DecryptResource(item.EncryptedEnv, "compose-env", item.ID.String(), "compose-env")
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	if err = json.Unmarshal(plain, &values); err != nil {
		return nil, err
	}
	if values == nil {
		values = map[string]string{}
	}
	return values, nil
}

func (s *Server) getServiceVariables(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	item, _, err := s.Store.GetComposeService(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	values, err := s.decryptServiceVariables(item)
	if err != nil {
		s.writeInternalError(w, r, 500, "decryption_failed", "stored service variables could not be read", err)
		return
	}
	writeJSON(w, 200, serviceVariableResponse(values, item.Revision))
}

func (s *Server) putServiceVariables(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	var input struct {
		Values map[string]string `json:"values"`
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.Values) == 0 {
		writeError(w, 400, "invalid_variables", "values must contain at least one variable")
		return
	}
	if err = validateServiceVariables(input.Values); err != nil {
		writeError(w, 400, "invalid_variables", err.Error())
		return
	}
	p := principal(r)
	for attempt := 0; attempt < 3; attempt++ {
		item, _, getErr := s.Store.GetComposeService(r.Context(), p.OrganizationID, id)
		if getErr != nil {
			writeStoreError(w, getErr)
			return
		}
		values, decryptErr := s.decryptServiceVariables(item)
		if decryptErr != nil {
			s.writeInternalError(w, r, 500, "decryption_failed", "stored service variables could not be read", decryptErr)
			return
		}
		additions := 0
		for name := range input.Values {
			if _, exists := values[name]; !exists {
				additions++
			}
		}
		if len(values)+additions > maxServiceVariables {
			writeError(w, 400, "invalid_variables", "a service may contain at most 256 variables")
			return
		}
		for name, value := range input.Values {
			values[name] = value
		}
		plain, marshalErr := json.Marshal(values)
		if marshalErr != nil || len(plain) > maxServiceEnvironmentJSON {
			writeError(w, 400, "invalid_variables", "the combined service environment exceeds 1 MiB")
			return
		}
		encrypted, encryptErr := s.Box.Encrypt(plain, composeEnvironmentContext(id))
		if encryptErr != nil {
			s.writeInternalError(w, r, 500, "encryption_failed", "service variables could not be encrypted", encryptErr)
			return
		}
		updated, updateErr := s.Store.ReplaceComposeServiceEnvironment(r.Context(), p.OrganizationID, id, item.Revision, encrypted)
		if errors.Is(updateErr, store.ErrBusy) {
			continue
		}
		if updateErr != nil {
			writeStoreError(w, updateErr)
			return
		}
		names := make([]string, 0, len(input.Values))
		for name := range input.Values {
			names = append(names, name)
		}
		sort.Strings(names)
		s.Store.Audit(r.Context(), &p, "service.variables.upsert", "compose_service", id.String(), r.RemoteAddr, map[string]any{"names": names, "count": len(names), "revision": updated.Revision})
		writeJSON(w, 200, serviceVariableResponse(values, updated.Revision))
		return
	}
	writeError(w, 409, "concurrent_update", "service changed while variables were being updated")
}

func (s *Server) deleteServiceVariable(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	name := r.PathValue("name")
	if err = validateServiceVariable(name, ""); err != nil {
		writeError(w, 400, "invalid_variables", err.Error())
		return
	}
	p := principal(r)
	for attempt := 0; attempt < 3; attempt++ {
		item, _, getErr := s.Store.GetComposeService(r.Context(), p.OrganizationID, id)
		if getErr != nil {
			writeStoreError(w, getErr)
			return
		}
		values, decryptErr := s.decryptServiceVariables(item)
		if decryptErr != nil {
			s.writeInternalError(w, r, 500, "decryption_failed", "stored service variables could not be read", decryptErr)
			return
		}
		if _, exists := values[name]; !exists {
			writeError(w, 404, "not_found", "service variable not found")
			return
		}
		delete(values, name)
		plain, _ := json.Marshal(values)
		encrypted := ""
		if len(values) > 0 {
			encrypted, err = s.Box.Encrypt(plain, composeEnvironmentContext(id))
			if err != nil {
				s.writeInternalError(w, r, 500, "encryption_failed", "service variables could not be encrypted", err)
				return
			}
		}
		updated, updateErr := s.Store.ReplaceComposeServiceEnvironment(r.Context(), p.OrganizationID, id, item.Revision, encrypted)
		if errors.Is(updateErr, store.ErrBusy) {
			continue
		}
		if updateErr != nil {
			writeStoreError(w, updateErr)
			return
		}
		s.Store.Audit(r.Context(), &p, "service.variables.delete", "compose_service", id.String(), r.RemoteAddr, map[string]any{"name": name, "revision": updated.Revision})
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeError(w, 409, "concurrent_update", "service changed while variables were being updated")
}
