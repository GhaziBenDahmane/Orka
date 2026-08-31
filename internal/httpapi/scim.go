package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/jackc/pgx/v5/pgconn"
)

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

const scimMaxPageSize = 100
const scimMaxPatchOperations = 100

type scimUserResponse struct {
	Schemas     []string         `json:"schemas"`
	ID          string           `json:"id"`
	ExternalID  string           `json:"externalId,omitempty"`
	UserName    string           `json:"userName"`
	DisplayName string           `json:"displayName,omitempty"`
	Active      bool             `json:"active"`
	Meta        scimResourceMeta `json:"meta"`
}

type scimResourceMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location"`
	Version      string    `json:"version"`
}

type scimUserInput struct {
	Schemas     []string `json:"schemas"`
	ExternalID  string   `json:"externalId"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName"`
	Active      *bool    `json:"active"`
}

type scimUserPatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
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
	item, err := s.Store.CreateSCIMTokenWithAudit(r.Context(), p, in.Name, in.DefaultRole, cryptox.Digest(token), expiresAt, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
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
	if err = s.Store.RevokeSCIMTokenWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) scimPrincipal(r *http.Request) (uuid.UUID, string, error) {
	token, ok := bearerToken(r)
	if !ok {
		return uuid.Nil, "", store.ErrNotFound
	}
	return s.Store.AuthenticateSCIM(r.Context(), cryptox.Digest(token))
}

func (s *Server) rateLimitSCIM(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			token = "missing"
		}
		limits := []struct {
			bucket string
			key    []byte
			limit  int
		}{
			{bucket: "scim-client", key: authenticationClientKey(r), limit: 1200},
			{bucket: "scim-credential", key: cryptox.Digest(token), limit: 600},
		}
		for _, item := range limits {
			allowed, retryAfter, err := s.Store.ConsumeRateLimit(r.Context(), item.bucket, item.key, item.limit, time.Minute)
			if err != nil {
				s.logger().ErrorContext(r.Context(), "SCIM rate limit failed", "error_type", fmt.Sprintf("%T", err), "request_id", requestID(r))
				scimError(w, http.StatusInternalServerError, "SCIM request could not be authorized")
				return
			}
			if !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				scimError(w, http.StatusTooManyRequests, "too many SCIM requests")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func scimJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func scimError(w http.ResponseWriter, status int, detail string) {
	scimJSON(w, status, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": strconv.Itoa(status), "detail": detail})
}

func scimVersion(revision int64) string {
	return `W/"` + strconv.FormatInt(revision, 10) + `"`
}

func scimSetResourceHeaders(w http.ResponseWriter, location string, revision int64) {
	w.Header().Set("Location", location)
	w.Header().Set("ETag", scimVersion(revision))
}

func scimPreconditionMatches(r *http.Request, revision int64) bool {
	value := strings.TrimSpace(r.Header.Get("If-Match"))
	if value == "" || value == "*" {
		return true
	}
	wanted := scimVersion(revision)
	for _, candidate := range strings.Split(value, ",") {
		if strings.TrimSpace(candidate) == wanted {
			return true
		}
	}
	return false
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
	scimJSON(w, 200, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":   map[string]bool{"supported": true}, "bulk": map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter": map[string]any{"supported": true, "maxResults": scimMaxPageSize}, "changePassword": map[string]bool{"supported": false},
		"sort": map[string]bool{"supported": false}, "etag": map[string]bool{"supported": true},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer token", "description": "Organization-scoped SCIM provisioning token", "specUri": "https://www.rfc-editor.org/info/rfc6750", "primary": true}},
	})
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
		match := regexp.MustCompile(`(?i)^(userName|externalId)\s+eq\s+"([^"]+)"$`).FindStringSubmatch(filter)
		if len(match) != 3 {
			scimError(w, 400, "only userName eq and externalId eq filters are supported")
			return
		}
		if strings.EqualFold(match[1], "userName") {
			from += ` AND lower(u.email)=lower($2)`
		} else {
			from += ` AND EXISTS(SELECT 1 FROM scim_user_defaults d WHERE d.organization_id=$1 AND d.user_id=u.id AND d.external_id=$2)`
		}
		args = append(args, match[2])
	}
	var total int
	if err = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*)`+from, args...).Scan(&total); err != nil {
		scimError(w, 500, "query failed")
		return
	}
	limitParameter := len(args) + 1
	query := `SELECT u.id,u.email,u.display_name,
		EXISTS(SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$1),
		COALESCE((SELECT d.external_id FROM scim_user_defaults d WHERE d.user_id=u.id AND d.organization_id=$1),''),
		COALESCE((SELECT d.created_at FROM scim_user_defaults d WHERE d.user_id=u.id AND d.organization_id=$1),(SELECT m.created_at FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$1),u.created_at),
		COALESCE((SELECT d.updated_at FROM scim_user_defaults d WHERE d.user_id=u.id AND d.organization_id=$1),(SELECT m.created_at FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$1),u.created_at),
		COALESCE((SELECT d.revision FROM scim_user_defaults d WHERE d.user_id=u.id AND d.organization_id=$1),1)` + from +
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
		var email, name, externalID string
		var active bool
		var createdAt, updatedAt time.Time
		var revision int64
		if err := rows.Scan(&id, &email, &name, &active, &externalID, &createdAt, &updatedAt, &revision); err != nil {
			scimError(w, 500, "query failed")
			return
		}
		resources = append(resources, makeSCIMUser(id, externalID, email, name, active, createdAt, updatedAt, revision, s.PublicURL))
	}
	if err = rows.Err(); err != nil {
		scimError(w, 500, "query failed")
		return
	}
	scimJSON(w, 200, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": total, "startIndex": startIndex, "itemsPerPage": len(resources), "Resources": resources})
}
func (s *Server) createSCIMUser(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, role string) {
	var in scimUserInput
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
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	if len(in.ExternalID) > 1024 {
		scimError(w, 400, "externalId must not exceed 1024 bytes")
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
	var externalID *string
	if in.ExternalID != "" {
		externalID = &in.ExternalID
	}
	var storedExternalID string
	var createdAt, updatedAt time.Time
	var revision int64
	err = tx.QueryRow(r.Context(), `INSERT INTO scim_user_defaults(organization_id,user_id,default_role,external_id) VALUES($1,$2,$3,$4)
		ON CONFLICT(organization_id,user_id) DO UPDATE SET default_role=excluded.default_role,external_id=COALESCE(excluded.external_id,scim_user_defaults.external_id),updated_at=now(),revision=scim_user_defaults.revision+1
		RETURNING COALESCE(external_id,''),created_at,updated_at,revision`, orgID, userID, role, externalID).Scan(&storedExternalID, &createdAt, &updatedAt, &revision)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		scimError(w, 409, "externalId is already assigned in this organization")
		return
	}
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
	if err = s.Store.AuditOrganizationTx(r.Context(), tx, orgID, "scim.user.create", "user", userID.String(), r.RemoteAddr, map[string]any{"active": active}); err != nil {
		scimError(w, 500, "create failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		scimError(w, 500, "create failed")
		return
	}
	item := makeSCIMUser(userID, storedExternalID, email, displayName, active, createdAt, updatedAt, revision, s.PublicURL)
	scimSetResourceHeaders(w, item.Meta.Location, revision)
	scimJSON(w, 201, item)
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
		var email, name, externalID string
		var active bool
		var createdAt, updatedAt time.Time
		var revision int64
		err = s.Store.Pool.QueryRow(r.Context(), `SELECT u.email,u.display_name,
			EXISTS(SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$2),
			COALESCE((SELECT d.external_id FROM scim_user_defaults d WHERE d.user_id=u.id AND d.organization_id=$2),''),
			COALESCE((SELECT d.created_at FROM scim_user_defaults d WHERE d.user_id=u.id AND d.organization_id=$2),(SELECT m.created_at FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$2),u.created_at),
			COALESCE((SELECT d.updated_at FROM scim_user_defaults d WHERE d.user_id=u.id AND d.organization_id=$2),(SELECT m.created_at FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$2),u.created_at),
			COALESCE((SELECT d.revision FROM scim_user_defaults d WHERE d.user_id=u.id AND d.organization_id=$2),1)
			FROM users u WHERE u.id=$1 AND (
				EXISTS(SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$2)
				OR EXISTS(SELECT 1 FROM scim_user_defaults d WHERE d.user_id=u.id AND d.organization_id=$2))`, userID, orgID).Scan(&email, &name, &active, &externalID, &createdAt, &updatedAt, &revision)
		if errors.Is(err, pgx.ErrNoRows) {
			scimError(w, 404, "user not found")
			return
		}
		if err != nil {
			scimError(w, 500, "query failed")
			return
		}
		item := makeSCIMUser(userID, externalID, email, name, active, createdAt, updatedAt, revision, s.PublicURL)
		scimSetResourceHeaders(w, item.Meta.Location, revision)
		scimJSON(w, 200, item)
	case http.MethodDelete:
		tx, txErr := s.Store.Pool.Begin(r.Context())
		if txErr != nil {
			scimError(w, 500, "delete failed")
			return
		}
		defer tx.Rollback(r.Context())
		var currentRole *string
		var revision int64
		if err = tx.QueryRow(r.Context(), `SELECT
			(SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2),
			COALESCE((SELECT revision FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2),1)
			FROM users u WHERE u.id=$2 AND (EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2)
				OR EXISTS(SELECT 1 FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2)) FOR UPDATE OF u`, orgID, userID).Scan(&currentRole, &revision); errors.Is(err, pgx.ErrNoRows) {
			scimError(w, 404, "user not found")
			return
		} else if err != nil {
			scimError(w, 500, "delete failed")
			return
		}
		if !scimPreconditionMatches(r, revision) {
			scimError(w, http.StatusPreconditionFailed, "resource version does not match If-Match")
			return
		}
		if currentRole != nil && *currentRole == "owner" {
			scimError(w, 409, "organization owners cannot be deprovisioned through SCIM")
			return
		}
		if _, err = tx.Exec(r.Context(), `DELETE FROM scim_group_members gm USING scim_groups g WHERE gm.group_id=g.id AND g.organization_id=$1 AND gm.user_id=$2`, orgID, userID); err == nil {
			_, err = tx.Exec(r.Context(), `DELETE FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2`, orgID, userID)
		}
		if err == nil {
			_, err = store.RevokeOrganizationMembershipSessionsTx(r.Context(), tx, orgID, userID)
		}
		if err == nil {
			_, err = tx.Exec(r.Context(), `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, userID)
		}
		if err != nil {
			scimError(w, 500, "delete failed")
			return
		}
		if err = s.Store.AuditOrganizationTx(r.Context(), tx, orgID, "scim.user.delete", "user", userID.String(), r.RemoteAddr, nil); err != nil {
			scimError(w, 500, "delete failed")
			return
		}
		if err = tx.Commit(r.Context()); err != nil {
			scimError(w, 500, "delete failed")
			return
		}
		w.WriteHeader(204)
	case http.MethodPut:
		s.replaceSCIMUser(w, r, orgID, userID, role)
	case http.MethodPatch:
		s.patchSCIMUser(w, r, orgID, userID, role)
	default:
		scimError(w, 405, "method not allowed")
	}
}

func (s *Server) replaceSCIMUser(w http.ResponseWriter, r *http.Request, orgID, userID uuid.UUID, fallbackRole string) {
	var in scimUserInput
	if !decodeSCIM(w, r, &in) {
		return
	}
	email, _, validEmail := canonicalEmail(in.UserName)
	if !validEmail {
		scimError(w, http.StatusBadRequest, "userName must be an email address")
		return
	}
	var validDisplayName bool
	in.DisplayName, validDisplayName = canonicalDisplayName(in.DisplayName)
	if !validDisplayName {
		scimError(w, http.StatusBadRequest, "displayName must not exceed 120 bytes")
		return
	}
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	if len(in.ExternalID) > 1024 {
		scimError(w, http.StatusBadRequest, "externalId must not exceed 1024 bytes")
		return
	}

	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		scimError(w, http.StatusInternalServerError, "replace failed")
		return
	}
	defer tx.Rollback(r.Context())
	var currentEmail, currentDisplayName string
	var currentRole *string
	var currentActive, shared bool
	var currentRevision int64
	err = tx.QueryRow(r.Context(), `SELECT u.email,u.display_name,
		(SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2),
		EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2),
		(EXISTS(SELECT 1 FROM memberships WHERE user_id=$2 AND organization_id<>$1)
			OR EXISTS(SELECT 1 FROM scim_user_defaults WHERE user_id=$2 AND organization_id<>$1)),
		COALESCE((SELECT revision FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2),1)
		FROM users u WHERE u.id=$2 AND (EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2)
			OR EXISTS(SELECT 1 FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2))
		FOR UPDATE OF u`, orgID, userID).Scan(&currentEmail, &currentDisplayName, &currentRole, &currentActive, &shared, &currentRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		scimError(w, http.StatusInternalServerError, "replace failed")
		return
	}
	if !scimPreconditionMatches(r, currentRevision) {
		scimError(w, http.StatusPreconditionFailed, "resource version does not match If-Match")
		return
	}
	active := currentActive
	if in.Active != nil {
		active = *in.Active
	}
	if !active && currentRole != nil && *currentRole == "owner" {
		scimError(w, http.StatusConflict, "organization owners cannot be deprovisioned through SCIM")
		return
	}
	if shared && email != currentEmail {
		scimError(w, http.StatusConflict, "userName is shared with another organization")
		return
	}
	if shared && in.DisplayName != currentDisplayName {
		scimError(w, http.StatusConflict, "displayName is shared with another organization")
		return
	}
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, email); err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE users SET email=$2,display_name=$3 WHERE id=$1`, userID, email, in.DisplayName)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		scimError(w, http.StatusConflict, "userName is already in use")
		return
	}
	if err != nil {
		scimError(w, http.StatusInternalServerError, "profile cannot be replaced")
		return
	}
	var externalID any
	if in.ExternalID != "" {
		externalID = in.ExternalID
	}
	var createdAt, updatedAt time.Time
	var revision int64
	err = tx.QueryRow(r.Context(), `INSERT INTO scim_user_defaults(organization_id,user_id,default_role,external_id,revision)
		VALUES($1,$2,$3,$4,2) ON CONFLICT(organization_id,user_id) DO UPDATE SET external_id=excluded.external_id,updated_at=now(),revision=scim_user_defaults.revision+1
		RETURNING created_at,updated_at,revision`, orgID, userID, fallbackRole, externalID).Scan(&createdAt, &updatedAt, &revision)
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		scimError(w, http.StatusConflict, "externalId is already assigned in this organization")
		return
	}
	if err != nil {
		scimError(w, http.StatusInternalServerError, "externalId cannot be replaced")
		return
	}
	if active {
		_, err = tx.Exec(r.Context(), `INSERT INTO memberships(organization_id,user_id,role)
			SELECT organization_id,user_id,default_role FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2
			ON CONFLICT(organization_id,user_id) DO UPDATE SET role=CASE WHEN memberships.role='owner' THEN 'owner' ELSE excluded.role END`, orgID, userID)
	} else if _, err = tx.Exec(r.Context(), `DELETE FROM scim_group_members gm USING scim_groups g WHERE gm.group_id=g.id AND g.organization_id=$1 AND gm.user_id=$2`, orgID, userID); err == nil {
		if _, err = store.RevokeOrganizationMembershipSessionsTx(r.Context(), tx, orgID, userID); err == nil {
			_, err = tx.Exec(r.Context(), `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, userID)
		}
	}
	if err != nil {
		scimError(w, http.StatusInternalServerError, "membership cannot be replaced")
		return
	}
	if err = s.Store.AuditOrganizationTx(r.Context(), tx, orgID, "scim.user.replace", "user", userID.String(), r.RemoteAddr, map[string]any{"active": active}); err != nil {
		scimError(w, http.StatusInternalServerError, "replace failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		scimError(w, http.StatusInternalServerError, "replace failed")
		return
	}
	item := makeSCIMUser(userID, in.ExternalID, email, in.DisplayName, active, createdAt, updatedAt, revision, s.PublicURL)
	scimSetResourceHeaders(w, item.Meta.Location, revision)
	scimJSON(w, http.StatusOK, item)
}

func (s *Server) patchSCIMUser(w http.ResponseWriter, r *http.Request, orgID, userID uuid.UUID, role string) {
	var in struct {
		Schemas    []string                 `json:"schemas"`
		Operations []scimUserPatchOperation `json:"Operations"`
	}
	if !decodeSCIM(w, r, &in) {
		return
	}
	operations, err := normalizeSCIMUserPatchOperations(in.Operations)
	if err != nil {
		scimError(w, 400, err.Error())
		return
	}
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		scimError(w, 500, "patch failed")
		return
	}
	defer tx.Rollback(r.Context())
	var currentEmail string
	var currentRole *string
	var shared bool
	var currentRevision int64
	err = tx.QueryRow(r.Context(), `SELECT u.email,
		(SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2),
		(EXISTS(SELECT 1 FROM memberships WHERE user_id=$2 AND organization_id<>$1)
			OR EXISTS(SELECT 1 FROM scim_user_defaults WHERE user_id=$2 AND organization_id<>$1)),
		COALESCE((SELECT revision FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2),1)
		FROM users u WHERE u.id=$2 AND (EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2)
			OR EXISTS(SELECT 1 FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2)
		) FOR UPDATE OF u`, orgID, userID).Scan(&currentEmail, &currentRole, &shared, &currentRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		scimError(w, 404, "user not found")
		return
	}
	if err != nil {
		scimError(w, 500, "patch failed")
		return
	}
	if !scimPreconditionMatches(r, currentRevision) {
		scimError(w, http.StatusPreconditionFailed, "resource version does not match If-Match")
		return
	}
	if _, err = tx.Exec(r.Context(), `INSERT INTO scim_user_defaults(organization_id,user_id,default_role) VALUES($1,$2,$3) ON CONFLICT(organization_id,user_id) DO NOTHING`, orgID, userID, role); err != nil {
		scimError(w, 500, "SCIM ownership could not be established")
		return
	}
	for _, operation := range operations {
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
					if _, err = store.RevokeOrganizationMembershipSessionsTx(r.Context(), tx, orgID, userID); err == nil {
						_, err = tx.Exec(r.Context(), `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, userID)
					}
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
		case "username":
			emailValue, ok := operation.Value.(string)
			email, _, valid := canonicalEmail(emailValue)
			if !ok || !valid {
				scimError(w, 400, "userName must be an email address")
				return
			}
			if email != currentEmail && shared {
				scimError(w, 409, "userName is shared with another organization")
				return
			}
			if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, email); err == nil {
				_, err = tx.Exec(r.Context(), `UPDATE users SET email=$2 WHERE id=$1`, userID, email)
			}
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				scimError(w, 409, "userName is already in use")
				return
			}
			if err != nil {
				scimError(w, 500, "userName cannot be updated")
				return
			}
			currentEmail = email
		case "externalid":
			externalID, ok := operation.Value.(string)
			externalID = strings.TrimSpace(externalID)
			if !ok || len(externalID) > 1024 {
				scimError(w, 400, "externalId must be a string no longer than 1024 bytes")
				return
			}
			var storedExternalID any
			if externalID != "" {
				storedExternalID = externalID
			}
			_, err = tx.Exec(r.Context(), `INSERT INTO scim_user_defaults(organization_id,user_id,default_role,external_id) VALUES($1,$2,$3,$4) ON CONFLICT(organization_id,user_id) DO UPDATE SET external_id=excluded.external_id`, orgID, userID, role, storedExternalID)
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				scimError(w, 409, "externalId is already assigned in this organization")
				return
			}
			if err != nil {
				scimError(w, 500, "externalId cannot be updated")
				return
			}
		default:
			scimError(w, 400, "unsupported patch path")
			return
		}
	}
	var revision int64
	if err = tx.QueryRow(r.Context(), `UPDATE scim_user_defaults SET updated_at=now(),revision=revision+1 WHERE organization_id=$1 AND user_id=$2 RETURNING revision`, orgID, userID).Scan(&revision); err != nil {
		scimError(w, 500, "resource version could not be updated")
		return
	}
	if err = s.Store.AuditOrganizationTx(r.Context(), tx, orgID, "scim.user.patch", "user", userID.String(), r.RemoteAddr, map[string]any{"operationCount": len(operations)}); err != nil {
		scimError(w, 500, "patch failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		scimError(w, 500, "patch failed")
		return
	}
	w.Header().Set("ETag", scimVersion(revision))
	w.WriteHeader(204)
}

func normalizeSCIMUserPatchOperations(input []scimUserPatchOperation) ([]scimUserPatchOperation, error) {
	if len(input) > scimMaxPatchOperations {
		return nil, errors.New("patch request exceeds 100 operations")
	}
	result := make([]scimUserPatchOperation, 0, len(input))
	for _, operation := range input {
		if !strings.EqualFold(operation.Op, "replace") {
			return nil, errors.New("only replace operations are supported")
		}
		operation.Path = strings.TrimSpace(operation.Path)
		if operation.Path != "" {
			result = append(result, operation)
			continue
		}
		attributes, ok := operation.Value.(map[string]any)
		if !ok || len(attributes) == 0 {
			return nil, errors.New("a pathless replace operation must contain attributes")
		}
		normalized := make(map[string]any, len(attributes))
		for name, value := range attributes {
			key := strings.ToLower(strings.TrimSpace(name))
			switch key {
			case "active", "username", "displayname", "externalid":
			default:
				return nil, fmt.Errorf("unsupported patch attribute %q", name)
			}
			if _, duplicate := normalized[key]; duplicate {
				return nil, fmt.Errorf("duplicate patch attribute %q", name)
			}
			normalized[key] = value
		}
		for _, key := range []string{"username", "displayname", "externalid", "active"} {
			if value, exists := normalized[key]; exists {
				result = append(result, scimUserPatchOperation{Op: "replace", Path: key, Value: value})
			}
		}
	}
	if len(result) == 0 {
		return nil, errors.New("at least one patch operation is required")
	}
	if len(result) > scimMaxPatchOperations {
		return nil, errors.New("patch request exceeds 100 expanded operations")
	}
	return result, nil
}

func makeSCIMUser(id uuid.UUID, externalID, email, name string, active bool, createdAt, updatedAt time.Time, revision int64, baseURL string) scimUserResponse {
	location := strings.TrimRight(baseURL, "/") + "/scim/v2/Users/" + id.String()
	return scimUserResponse{
		Schemas: []string{scimUserSchema}, ID: id.String(), ExternalID: externalID, UserName: email, DisplayName: name, Active: active,
		Meta: scimResourceMeta{ResourceType: "User", Created: createdAt, LastModified: updatedAt, Location: location, Version: scimVersion(revision)},
	}
}
