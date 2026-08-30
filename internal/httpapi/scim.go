package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

const scimMaxPageSize = 100

type scimUserResponse struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id"`
	UserName    string            `json:"userName"`
	DisplayName string            `json:"displayName,omitempty"`
	Active      bool              `json:"active"`
	Meta        map[string]string `json:"meta,omitempty"`
}

func (s *Server) createSCIMToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name          string `json:"name"`
		DefaultRole   string `json:"defaultRole"`
		ExpiresInDays int    `json:"expiresInDays"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		in.Name = "default"
	}
	if len(in.Name) > 120 {
		writeError(w, 400, "invalid_name", "name must not exceed 120 bytes")
		return
	}
	if in.DefaultRole == "" {
		in.DefaultRole = "developer"
	}
	if in.ExpiresInDays == 0 {
		in.ExpiresInDays = 90
	}
	if roleRank(in.DefaultRole) < 1 || in.DefaultRole == "owner" {
		writeError(w, 400, "invalid_role", "default role must be admin, developer, or viewer")
		return
	}
	if in.ExpiresInDays < 1 || in.ExpiresInDays > 365 {
		writeError(w, 400, "invalid_expiry", "expiry must be from 1 to 365 days")
		return
	}
	token, err := auth.NewToken()
	if err != nil {
		s.writeInternalError(w, r, 500, "token_failed", "SCIM token could not be generated", err)
		return
	}
	p := principal(r)
	expiresAt := time.Now().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour)
	item, err := s.Store.CreateSCIMToken(r.Context(), p.OrganizationID, in.Name, in.DefaultRole, cryptox.Digest(token), expiresAt)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "scim.token.create", "scim_token", item.ID.String(), r.RemoteAddr, map[string]any{"name": item.Name, "defaultRole": item.DefaultRole, "expiresAt": item.ExpiresAt})
	writeJSON(w, 201, map[string]any{"scimToken": item, "token": token, "baseUrl": s.PublicURL + "/scim/v2"})
}

func (s *Server) listSCIMTokens(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListSCIMTokens(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) revokeSCIMToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("tokenID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid SCIM token id")
		return
	}
	p := principal(r)
	if err = s.Store.RevokeSCIMToken(r.Context(), p.OrganizationID, id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "scim.token.revoke", "scim_token", id.String(), r.RemoteAddr, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) scimPrincipal(r *http.Request) (uuid.UUID, string, error) {
	token, ok := bearerToken(r)
	if !ok {
		return uuid.Nil, "", store.ErrNotFound
	}
	return s.Store.AuthenticateSCIM(r.Context(), cryptox.Digest(token))
}
func scimJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func scimError(w http.ResponseWriter, status int, detail string) {
	scimJSON(w, status, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": strconv.Itoa(status), "detail": detail})
}

// decodeSCIM keeps the platform request bound while allowing extension
// attributes, as required by SCIM's extensible schema model. Unsupported
// attributes are ignored instead of making otherwise valid provider payloads
// fail strict platform-API decoding.
func decodeSCIM(w http.ResponseWriter, r *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" && mediaType != "application/scim+json" {
		scimError(w, http.StatusUnsupportedMediaType, "request Content-Type must be application/scim+json or application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 3<<20)
	decoder := json.NewDecoder(r.Body)
	if err = decoder.Decode(target); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			scimError(w, http.StatusRequestEntityTooLarge, "SCIM request body exceeds the endpoint limit")
		} else {
			scimError(w, http.StatusBadRequest, "request body must contain one valid JSON object")
		}
		return false
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			scimError(w, http.StatusRequestEntityTooLarge, "SCIM request body exceeds the endpoint limit")
		} else {
			scimError(w, http.StatusBadRequest, "request must contain one JSON value")
		}
		return false
	}
	return true
}

func scimPage(r *http.Request) (startIndex, count int, err error) {
	startIndex, count = 1, scimMaxPageSize
	if raw := r.URL.Query().Get("startIndex"); raw != "" {
		startIndex, err = strconv.Atoi(raw)
		if err != nil || startIndex < 1 {
			return 0, 0, errors.New("startIndex must be a positive integer")
		}
	}
	if raw := r.URL.Query().Get("count"); raw != "" {
		count, err = strconv.Atoi(raw)
		if err != nil || count < 0 || count > scimMaxPageSize {
			return 0, 0, errors.New("count must be between 0 and 100")
		}
	}
	return startIndex, count, nil
}

func (s *Server) scimServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	scimJSON(w, 200, map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}, "patch": map[string]bool{"supported": true}, "bulk": map[string]bool{"supported": false}, "filter": map[string]any{"supported": true, "maxResults": 100}, "changePassword": map[string]bool{"supported": false}, "sort": map[string]bool{"supported": false}})
}

func (s *Server) scimUsers(w http.ResponseWriter, r *http.Request) {
	orgID, role, err := s.scimPrincipal(r)
	if err != nil {
		scimError(w, 401, "invalid SCIM token")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listSCIMUsers(w, r, orgID)
	case http.MethodPost:
		s.createSCIMUser(w, r, orgID, role)
	default:
		scimError(w, 405, "method not allowed")
	}
}
func (s *Server) listSCIMUsers(w http.ResponseWriter, r *http.Request, orgID uuid.UUID) {
	startIndex, count, err := scimPage(r)
	if err != nil {
		scimError(w, http.StatusBadRequest, err.Error())
		return
	}
	from := ` FROM users u
		WHERE (EXISTS(SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$1)
			OR EXISTS(SELECT 1 FROM scim_user_defaults d WHERE d.user_id=u.id AND d.organization_id=$1))`
	args := []any{orgID}
	if filter := r.URL.Query().Get("filter"); filter != "" {
		match := regexp.MustCompile(`(?i)^userName\s+eq\s+"([^"]+)"$`).FindStringSubmatch(filter)
		if len(match) != 2 {
			scimError(w, 400, "only userName eq filters are supported")
			return
		}
		from += ` AND lower(u.email)=lower($2)`
		args = append(args, match[1])
	}
	var total int
	if err = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*)`+from, args...).Scan(&total); err != nil {
		scimError(w, 500, "query failed")
		return
	}
	limitParameter := len(args) + 1
	query := `SELECT u.id,u.email,u.display_name,
		EXISTS(SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$1)` + from +
		` ORDER BY u.email LIMIT $` + strconv.Itoa(limitParameter) + ` OFFSET $` + strconv.Itoa(limitParameter+1)
	pageArgs := append(append([]any(nil), args...), count, startIndex-1)
	rows, err := s.Store.Pool.Query(r.Context(), query, pageArgs...)
	if err != nil {
		scimError(w, 500, "query failed")
		return
	}
	defer rows.Close()
	resources := []scimUserResponse{}
	for rows.Next() {
		var id uuid.UUID
		var email, name string
		var active bool
		if err := rows.Scan(&id, &email, &name, &active); err != nil {
			scimError(w, 500, "query failed")
			return
		}
		resources = append(resources, makeSCIMUser(id, email, name, active, s.PublicURL))
	}
	if err = rows.Err(); err != nil {
		scimError(w, 500, "query failed")
		return
	}
	scimJSON(w, 200, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": total, "startIndex": startIndex, "itemsPerPage": len(resources), "Resources": resources})
}
func (s *Server) createSCIMUser(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, role string) {
	var in struct {
		Schemas     []string `json:"schemas"`
		UserName    string   `json:"userName"`
		DisplayName string   `json:"displayName"`
		Active      *bool    `json:"active"`
	}
	if !decodeSCIM(w, r, &in) {
		return
	}
	email, _, validEmail := canonicalEmail(in.UserName)
	if !validEmail {
		scimError(w, 400, "userName must be an email address")
		return
	}
	var validDisplayName bool
	in.DisplayName, validDisplayName = canonicalDisplayName(in.DisplayName)
	if !validDisplayName {
		scimError(w, 400, "displayName must not exceed 120 bytes")
		return
	}
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		scimError(w, 500, "create failed")
		return
	}
	defer tx.Rollback(r.Context())
	var lockedOrganizationID uuid.UUID
	if err = tx.QueryRow(r.Context(), `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, orgID).Scan(&lockedOrganizationID); errors.Is(err, pgx.ErrNoRows) {
		scimError(w, 404, "organization not found")
		return
	} else if err != nil {
		scimError(w, 500, "create failed")
		return
	}
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, email); err != nil {
		scimError(w, 500, "create failed")
		return
	}
	var userID uuid.UUID
	var displayName string
	err = tx.QueryRow(r.Context(), `SELECT id,display_name FROM users WHERE email=$1 AND disabled_at IS NULL`, email).Scan(&userID, &displayName)
	if errors.Is(err, pgx.ErrNoRows) {
		userID = uuid.New()
		_, err = tx.Exec(r.Context(), `INSERT INTO users(id,email,password_hash,display_name) VALUES($1,$2,$3,$4)`, userID, email, "!scim:"+uuid.NewString(), in.DisplayName)
		displayName = in.DisplayName
	}
	if err != nil {
		scimError(w, 409, "user cannot be provisioned")
		return
	}
	active := in.Active == nil || *in.Active
	_, err = tx.Exec(r.Context(), `INSERT INTO scim_user_defaults(organization_id,user_id,default_role) VALUES($1,$2,$3) ON CONFLICT(organization_id,user_id) DO UPDATE SET default_role=excluded.default_role`, orgID, userID, role)
	if err == nil && active {
		_, err = tx.Exec(r.Context(), `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(organization_id,user_id) DO UPDATE SET role=CASE WHEN memberships.role='owner' THEN 'owner' ELSE excluded.role END`, orgID, userID, role)
	}
	if err != nil {
		scimError(w, 500, "membership cannot be provisioned")
		return
	}
	if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2)`, orgID, userID).Scan(&active); err != nil {
		scimError(w, 500, "membership cannot be provisioned")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		scimError(w, 500, "create failed")
		return
	}
	scimJSON(w, 201, makeSCIMUser(userID, email, displayName, active, s.PublicURL))
}
func (s *Server) scimUser(w http.ResponseWriter, r *http.Request) {
	orgID, role, err := s.scimPrincipal(r)
	if err != nil {
		scimError(w, 401, "invalid SCIM token")
		return
	}
	userID, err := uuid.Parse(r.PathValue("userID"))
	if err != nil {
		scimError(w, 404, "user not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		var email, name string
		var active bool
		err = s.Store.Pool.QueryRow(r.Context(), `SELECT u.email,u.display_name,
			EXISTS(SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$2)
			FROM users u WHERE u.id=$1 AND (
				EXISTS(SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$2)
				OR EXISTS(SELECT 1 FROM scim_user_defaults d WHERE d.user_id=u.id AND d.organization_id=$2))`, userID, orgID).Scan(&email, &name, &active)
		if errors.Is(err, pgx.ErrNoRows) {
			scimError(w, 404, "user not found")
			return
		}
		if err != nil {
			scimError(w, 500, "query failed")
			return
		}
		scimJSON(w, 200, makeSCIMUser(userID, email, name, active, s.PublicURL))
	case http.MethodDelete:
		var currentRole *string
		if err = s.Store.Pool.QueryRow(r.Context(), `SELECT (SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2)
			WHERE EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2)
				OR EXISTS(SELECT 1 FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2)`, orgID, userID).Scan(&currentRole); err != nil {
			scimError(w, 404, "user not found")
			return
		}
		if currentRole != nil && *currentRole == "owner" {
			scimError(w, 409, "organization owners cannot be deprovisioned through SCIM")
			return
		}
		tx, txErr := s.Store.Pool.Begin(r.Context())
		if txErr != nil {
			scimError(w, 500, "delete failed")
			return
		}
		defer tx.Rollback(r.Context())
		if _, err = tx.Exec(r.Context(), `DELETE FROM scim_group_members gm USING scim_groups g WHERE gm.group_id=g.id AND g.organization_id=$1 AND gm.user_id=$2`, orgID, userID); err == nil {
			_, err = tx.Exec(r.Context(), `DELETE FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2`, orgID, userID)
		}
		if err == nil {
			_, err = tx.Exec(r.Context(), `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, userID)
		}
		if err != nil {
			scimError(w, 500, "delete failed")
			return
		}
		if err = tx.Commit(r.Context()); err != nil {
			scimError(w, 500, "delete failed")
			return
		}
		w.WriteHeader(204)
	case http.MethodPatch:
		s.patchSCIMUser(w, r, orgID, userID, role)
	default:
		scimError(w, 405, "method not allowed")
	}
}
func (s *Server) patchSCIMUser(w http.ResponseWriter, r *http.Request, orgID, userID uuid.UUID, role string) {
	var in struct {
		Schemas    []string `json:"schemas"`
		Operations []struct {
			Op    string `json:"op"`
			Path  string `json:"path"`
			Value any    `json:"value"`
		} `json:"Operations"`
	}
	if !decodeSCIM(w, r, &in) {
		return
	}
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		scimError(w, 500, "patch failed")
		return
	}
	defer tx.Rollback(r.Context())
	var currentRole *string
	var shared bool
	err = tx.QueryRow(r.Context(), `SELECT
		(SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2),
		(EXISTS(SELECT 1 FROM memberships WHERE user_id=$2 AND organization_id<>$1)
			OR EXISTS(SELECT 1 FROM scim_user_defaults WHERE user_id=$2 AND organization_id<>$1))
		FROM users u WHERE u.id=$2 AND (EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2)
			OR EXISTS(SELECT 1 FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2)
		) FOR UPDATE OF u`, orgID, userID).Scan(&currentRole, &shared)
	if errors.Is(err, pgx.ErrNoRows) {
		scimError(w, 404, "user not found")
		return
	}
	if err != nil {
		scimError(w, 500, "patch failed")
		return
	}
	for _, operation := range in.Operations {
		if !strings.EqualFold(operation.Op, "replace") {
			scimError(w, 400, "only replace operations are supported")
			return
		}
		switch strings.ToLower(operation.Path) {
		case "active":
			active, ok := operation.Value.(bool)
			if !ok {
				scimError(w, 400, "active must be boolean")
				return
			}
			if !active {
				if currentRole != nil && *currentRole == "owner" {
					scimError(w, 409, "organization owners cannot be deprovisioned through SCIM")
					return
				}
				if _, err = tx.Exec(r.Context(), `DELETE FROM scim_group_members gm USING scim_groups g WHERE gm.group_id=g.id AND g.organization_id=$1 AND gm.user_id=$2`, orgID, userID); err == nil {
					_, err = tx.Exec(r.Context(), `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, userID)
				}
			} else {
				_, err = tx.Exec(r.Context(), `INSERT INTO scim_user_defaults(organization_id,user_id,default_role) VALUES($1,$2,$3) ON CONFLICT(organization_id,user_id) DO NOTHING`, orgID, userID, role)
				if err == nil {
					_, err = tx.Exec(r.Context(), `INSERT INTO memberships(organization_id,user_id,role) SELECT organization_id,user_id,default_role FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2 ON CONFLICT DO NOTHING`, orgID, userID)
				}
			}
			if err != nil {
				scimError(w, 500, "membership cannot be updated")
				return
			}
		case "displayname":
			name, ok := operation.Value.(string)
			if !ok {
				scimError(w, 400, "displayName must be a string")
				return
			}
			name, ok = canonicalDisplayName(name)
			if !ok {
				scimError(w, 400, "displayName must not exceed 120 bytes")
				return
			}
			if shared {
				scimError(w, 409, "displayName is shared with another organization")
				return
			}
			if _, err = tx.Exec(r.Context(), `UPDATE users SET display_name=$2 WHERE id=$1`, userID, name); err != nil {
				scimError(w, 500, "displayName cannot be updated")
				return
			}
		default:
			scimError(w, 400, "unsupported patch path")
			return
		}
	}
	if err = tx.Commit(r.Context()); err != nil {
		scimError(w, 500, "patch failed")
		return
	}
	w.WriteHeader(204)
}
func makeSCIMUser(id uuid.UUID, email, name string, active bool, baseURL string) scimUserResponse {
	return scimUserResponse{Schemas: []string{scimUserSchema}, ID: id.String(), UserName: email, DisplayName: name, Active: active, Meta: map[string]string{"resourceType": "User", "location": baseURL + "/scim/v2/Users/" + id.String()}}
}
