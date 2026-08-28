package httpapi

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

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
		Name        string `json:"name"`
		DefaultRole string `json:"defaultRole"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Name == "" {
		in.Name = "default"
	}
	if in.DefaultRole == "" {
		in.DefaultRole = "developer"
	}
	if roleRank(in.DefaultRole) < 1 || in.DefaultRole == "owner" {
		writeError(w, 400, "invalid_role", "default role must be admin, developer, or viewer")
		return
	}
	token, err := auth.NewToken()
	if err != nil {
		writeError(w, 500, "token_failed", err.Error())
		return
	}
	p := principal(r)
	if err = s.Store.CreateSCIMToken(r.Context(), p.OrganizationID, in.Name, in.DefaultRole, cryptox.Digest(token)); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "scim.token.create", "organization", p.OrganizationID.String(), r.RemoteAddr, nil)
	writeJSON(w, 201, map[string]string{"token": token, "baseUrl": s.PublicURL + "/scim/v2"})
}

func (s *Server) scimPrincipal(r *http.Request) (uuid.UUID, string, error) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		return uuid.Nil, "", store.ErrNotFound
	}
	return s.Store.AuthenticateSCIM(r.Context(), cryptox.Digest(token))
}
func scimJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/scim+json")
	writeJSON(w, status, value)
}
func scimError(w http.ResponseWriter, status int, detail string) {
	scimJSON(w, status, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": status, "detail": detail})
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
	query := `SELECT u.id,u.email,u.display_name FROM users u JOIN memberships m ON m.user_id=u.id WHERE m.organization_id=$1`
	args := []any{orgID}
	if filter := r.URL.Query().Get("filter"); filter != "" {
		match := regexp.MustCompile(`(?i)^userName\s+eq\s+"([^"]+)"$`).FindStringSubmatch(filter)
		if len(match) != 2 {
			scimError(w, 400, "only userName eq filters are supported")
			return
		}
		query += ` AND lower(u.email)=lower($2)`
		args = append(args, match[1])
	}
	query += ` ORDER BY u.email LIMIT 100`
	rows, err := s.Store.Pool.Query(r.Context(), query, args...)
	if err != nil {
		scimError(w, 500, "query failed")
		return
	}
	defer rows.Close()
	resources := []scimUserResponse{}
	for rows.Next() {
		var id uuid.UUID
		var email, name string
		if err := rows.Scan(&id, &email, &name); err != nil {
			scimError(w, 500, "query failed")
			return
		}
		resources = append(resources, makeSCIMUser(id, email, name, true, s.PublicURL))
	}
	scimJSON(w, 200, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": len(resources), "startIndex": 1, "itemsPerPage": len(resources), "Resources": resources})
}
func (s *Server) createSCIMUser(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, role string) {
	var in struct {
		Schemas     []string `json:"schemas"`
		UserName    string   `json:"userName"`
		DisplayName string   `json:"displayName"`
		Active      *bool    `json:"active"`
	}
	if !decode(w, r, &in) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.UserName))
	if !strings.Contains(email, "@") {
		scimError(w, 400, "userName must be an email address")
		return
	}
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		scimError(w, 500, "create failed")
		return
	}
	defer tx.Rollback(r.Context())
	var userID uuid.UUID
	err = tx.QueryRow(r.Context(), `SELECT id FROM users WHERE email=$1`, email).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		userID = uuid.New()
		_, err = tx.Exec(r.Context(), `INSERT INTO users(id,email,password_hash,display_name) VALUES($1,$2,$3,$4)`, userID, email, "!scim:"+uuid.NewString(), in.DisplayName)
	}
	if err != nil {
		scimError(w, 409, "user cannot be provisioned")
		return
	}
	active := in.Active == nil || *in.Active
	if active {
		_, err = tx.Exec(r.Context(), `INSERT INTO scim_user_defaults(organization_id,user_id,default_role) VALUES($1,$2,$3) ON CONFLICT(organization_id,user_id) DO UPDATE SET default_role=excluded.default_role`, orgID, userID, role)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(organization_id,user_id) DO UPDATE SET role=CASE WHEN memberships.role='owner' THEN 'owner' ELSE excluded.role END`, orgID, userID, role)
		}
	}
	if err != nil {
		scimError(w, 500, "membership cannot be provisioned")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		scimError(w, 500, "create failed")
		return
	}
	scimJSON(w, 201, makeSCIMUser(userID, email, in.DisplayName, active, s.PublicURL))
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
		err = s.Store.Pool.QueryRow(r.Context(), `SELECT u.email,u.display_name FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.id=$1 AND m.organization_id=$2`, userID, orgID).Scan(&email, &name)
		if errors.Is(err, pgx.ErrNoRows) {
			scimError(w, 404, "user not found")
			return
		}
		if err != nil {
			scimError(w, 500, "query failed")
			return
		}
		scimJSON(w, 200, makeSCIMUser(userID, email, name, true, s.PublicURL))
	case http.MethodDelete:
		var currentRole string
		if err = s.Store.Pool.QueryRow(r.Context(), `SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, userID).Scan(&currentRole); err != nil {
			scimError(w, 404, "user not found")
			return
		}
		if currentRole == "owner" {
			scimError(w, 409, "organization owners cannot be deprovisioned through SCIM")
			return
		}
		tx, txErr := s.Store.Pool.Begin(r.Context())
		if txErr != nil {
			scimError(w, 500, "delete failed")
			return
		}
		defer tx.Rollback(r.Context())
		_, _ = tx.Exec(r.Context(), `DELETE FROM scim_group_members gm USING scim_groups g WHERE gm.group_id=g.id AND g.organization_id=$1 AND gm.user_id=$2`, orgID, userID)
		_, _ = tx.Exec(r.Context(), `DELETE FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2`, orgID, userID)
		tag, err := tx.Exec(r.Context(), `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, userID)
		if err != nil {
			scimError(w, 500, "delete failed")
			return
		}
		if tag.RowsAffected() == 0 {
			scimError(w, 404, "user not found")
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
	if !decode(w, r, &in) {
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
				var isOwner bool
				_ = s.Store.Pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2 AND role='owner')`, orgID, userID).Scan(&isOwner)
				if isOwner {
					scimError(w, 409, "organization owners cannot be deprovisioned through SCIM")
					return
				}
				_, _ = s.Store.Pool.Exec(r.Context(), `DELETE FROM scim_group_members gm USING scim_groups g WHERE gm.group_id=g.id AND g.organization_id=$1 AND gm.user_id=$2`, orgID, userID)
				_, _ = s.Store.Pool.Exec(r.Context(), `DELETE FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2`, orgID, userID)
				_, _ = s.Store.Pool.Exec(r.Context(), `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, userID)
			} else {
				_, _ = s.Store.Pool.Exec(r.Context(), `INSERT INTO scim_user_defaults(organization_id,user_id,default_role) VALUES($1,$2,$3) ON CONFLICT(organization_id,user_id) DO NOTHING`, orgID, userID, role)
				_, _ = s.Store.Pool.Exec(r.Context(), `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, orgID, userID, role)
			}
		case "displayname":
			name, ok := operation.Value.(string)
			if !ok {
				scimError(w, 400, "displayName must be a string")
				return
			}
			_, _ = s.Store.Pool.Exec(r.Context(), `UPDATE users SET display_name=$2 WHERE id=$1`, userID, name)
		default:
			scimError(w, 400, "unsupported patch path")
			return
		}
	}
	w.WriteHeader(204)
}
func makeSCIMUser(id uuid.UUID, email, name string, active bool, baseURL string) scimUserResponse {
	return scimUserResponse{Schemas: []string{scimUserSchema}, ID: id.String(), UserName: email, DisplayName: name, Active: active, Meta: map[string]string{"resourceType": "User", "location": baseURL + "/scim/v2/Users/" + id.String()}}
}
