package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"

type scimMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

type scimGroupResponse struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Role        string            `json:"role"`
	Members     []scimMember      `json:"members"`
	Meta        map[string]string `json:"meta"`
}

type scimGroupInput struct {
	ExternalID  string       `json:"externalId"`
	DisplayName string       `json:"displayName"`
	Role        string       `json:"role"`
	Members     []scimMember `json:"members"`
}

func (s *Server) scimGroups(w http.ResponseWriter, r *http.Request) {
	orgID, _, err := s.scimPrincipal(r)
	if err != nil {
		scimError(w, 401, "invalid SCIM token")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listSCIMGroups(w, r, orgID)
	case http.MethodPost:
		s.createSCIMGroup(w, r, orgID)
	default:
		scimError(w, 405, "method not allowed")
	}
}

func (s *Server) listSCIMGroups(w http.ResponseWriter, r *http.Request, orgID uuid.UUID) {
	startIndex, count, err := scimPage(r)
	if err != nil {
		scimError(w, http.StatusBadRequest, err.Error())
		return
	}
	from := ` FROM scim_groups WHERE organization_id=$1`
	args := []any{orgID}
	if filter := r.URL.Query().Get("filter"); filter != "" {
		match := regexp.MustCompile(`(?i)^displayName\s+eq\s+"([^"]+)"$`).FindStringSubmatch(filter)
		if len(match) != 2 {
			scimError(w, 400, "only displayName eq filters are supported")
			return
		}
		from += ` AND display_name=$2`
		args = append(args, match[1])
	}
	var total int
	if err = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*)`+from, args...).Scan(&total); err != nil {
		scimError(w, 500, "query failed")
		return
	}
	limitParameter := len(args) + 1
	query := `SELECT id` + from + ` ORDER BY display_name,id LIMIT $` + strconv.Itoa(limitParameter) + ` OFFSET $` + strconv.Itoa(limitParameter+1)
	pageArgs := append(append([]any(nil), args...), count, startIndex-1)
	rows, err := s.Store.Pool.Query(r.Context(), query, pageArgs...)
	if err != nil {
		scimError(w, 500, "query failed")
		return
	}
	defer rows.Close()
	items := []scimGroupResponse{}
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			scimError(w, 500, "query failed")
			return
		}
		item, loadErr := s.loadSCIMGroup(r.Context(), orgID, id)
		if loadErr != nil {
			scimError(w, 500, "query failed")
			return
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		scimError(w, 500, "query failed")
		return
	}
	scimJSON(w, 200, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": total, "startIndex": startIndex, "itemsPerPage": len(items), "Resources": items})
}

func (s *Server) createSCIMGroup(w http.ResponseWriter, r *http.Request, orgID uuid.UUID) {
	var in scimGroupInput
	if !decodeSCIM(w, r, &in) {
		return
	}
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.Role == "" {
		in.Role = "viewer"
	}
	if in.DisplayName == "" || !validSCIMRole(in.Role) {
		scimError(w, 400, "displayName and a valid role are required")
		return
	}
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		scimError(w, 500, "create failed")
		return
	}
	defer tx.Rollback(r.Context())
	id := uuid.New()
	var externalID *string
	if in.ExternalID != "" {
		externalID = &in.ExternalID
	}
	if _, err = tx.Exec(r.Context(), `INSERT INTO scim_groups(id,organization_id,external_id,display_name,role) VALUES($1,$2,$3,$4,$5)`, id, orgID, externalID, in.DisplayName, in.Role); err != nil {
		scimError(w, 409, "group already exists")
		return
	}
	if err = replaceSCIMMembers(r.Context(), tx, orgID, id, in.Members); err != nil {
		scimError(w, 400, err.Error())
		return
	}
	if err = s.Store.AuditOrganizationTx(r.Context(), tx, orgID, "scim.group.create", "scim_group", id.String(), r.RemoteAddr, map[string]any{"role": in.Role, "memberCount": len(in.Members)}); err != nil {
		scimError(w, 500, "create failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		scimError(w, 500, "create failed")
		return
	}
	item, _ := s.loadSCIMGroup(r.Context(), orgID, id)
	scimJSON(w, 201, item)
}

func (s *Server) scimGroup(w http.ResponseWriter, r *http.Request) {
	orgID, _, err := s.scimPrincipal(r)
	if err != nil {
		scimError(w, 401, "invalid SCIM token")
		return
	}
	id, err := uuid.Parse(r.PathValue("groupID"))
	if err != nil {
		scimError(w, 404, "group not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		item, loadErr := s.loadSCIMGroup(r.Context(), orgID, id)
		if loadErr != nil {
			scimError(w, 404, "group not found")
			return
		}
		scimJSON(w, 200, item)
	case http.MethodPatch:
		s.patchSCIMGroup(w, r, orgID, id)
	case http.MethodDelete:
		s.deleteSCIMGroup(w, r, orgID, id)
	default:
		scimError(w, 405, "method not allowed")
	}
}

func (s *Server) patchSCIMGroup(w http.ResponseWriter, r *http.Request, orgID, groupID uuid.UUID) {
	var in struct {
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
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
	var exists bool
	if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM scim_groups WHERE id=$1 AND organization_id=$2)`, groupID, orgID).Scan(&exists); err != nil {
		scimError(w, 500, "patch failed")
		return
	}
	if !exists {
		scimError(w, 404, "group not found")
		return
	}
	for _, op := range in.Operations {
		path := strings.TrimSpace(op.Path)
		if strings.EqualFold(path, "displayName") && strings.EqualFold(op.Op, "replace") {
			var name string
			if json.Unmarshal(op.Value, &name) != nil || strings.TrimSpace(name) == "" {
				scimError(w, 400, "displayName must be a non-empty string")
				return
			}
			_, err = tx.Exec(r.Context(), `UPDATE scim_groups SET display_name=$3,updated_at=now() WHERE id=$1 AND organization_id=$2`, groupID, orgID, strings.TrimSpace(name))
			if err != nil {
				scimError(w, 409, "displayName is already in use")
				return
			}
			continue
		}
		if strings.EqualFold(path, "role") && strings.EqualFold(op.Op, "replace") {
			var role string
			if json.Unmarshal(op.Value, &role) != nil || !validSCIMRole(role) {
				scimError(w, 400, "role must be admin, developer, or viewer")
				return
			}
			users, usersErr := groupUserIDs(r.Context(), tx, groupID)
			if usersErr != nil {
				scimError(w, 500, "role update failed")
				return
			}
			if _, err = tx.Exec(r.Context(), `UPDATE scim_groups SET role=$3,updated_at=now() WHERE id=$1 AND organization_id=$2`, groupID, orgID, role); err != nil {
				scimError(w, 500, "role update failed")
				return
			}
			for _, userID := range users {
				if err = reconcileSCIMRole(r.Context(), tx, orgID, userID); err != nil {
					scimError(w, 500, "role reconciliation failed")
					return
				}
			}
			continue
		}
		if match := regexp.MustCompile(`(?i)^members\[value\s+eq\s+"([^"]+)"\]$`).FindStringSubmatch(path); len(match) == 2 && strings.EqualFold(op.Op, "remove") {
			if err = removeSCIMMembers(r.Context(), tx, orgID, groupID, []scimMember{{Value: match[1]}}); err != nil {
				scimError(w, 400, err.Error())
				return
			}
			continue
		}
		if !strings.EqualFold(path, "members") {
			scimError(w, 400, "unsupported patch path")
			return
		}
		members, parseErr := decodeSCIMMembers(op.Value)
		if parseErr != nil {
			scimError(w, 400, parseErr.Error())
			return
		}
		switch strings.ToLower(op.Op) {
		case "replace":
			if err = replaceSCIMMembers(r.Context(), tx, orgID, groupID, members); err != nil {
				scimError(w, 400, err.Error())
				return
			}
		case "add":
			if err = addSCIMMembers(r.Context(), tx, orgID, groupID, members); err != nil {
				scimError(w, 400, err.Error())
				return
			}
		case "remove":
			if err = removeSCIMMembers(r.Context(), tx, orgID, groupID, members); err != nil {
				scimError(w, 400, err.Error())
				return
			}
		default:
			scimError(w, 400, "unsupported operation")
			return
		}
	}
	if err = s.Store.AuditOrganizationTx(r.Context(), tx, orgID, "scim.group.patch", "scim_group", groupID.String(), r.RemoteAddr, map[string]any{"operationCount": len(in.Operations)}); err != nil {
		scimError(w, 500, "patch failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		scimError(w, 500, "patch failed")
		return
	}
	w.WriteHeader(204)
}

func decodeSCIMMembers(raw json.RawMessage) ([]scimMember, error) {
	var members []scimMember
	if err := json.Unmarshal(raw, &members); err == nil {
		return members, nil
	}
	var wrapper struct {
		Members []scimMember `json:"members"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil || wrapper.Members == nil {
		return nil, errors.New("members value must be an array")
	}
	return wrapper.Members, nil
}

func (s *Server) deleteSCIMGroup(w http.ResponseWriter, r *http.Request, orgID, groupID uuid.UUID) {
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		scimError(w, 500, "delete failed")
		return
	}
	defer tx.Rollback(r.Context())
	users, err := groupUserIDs(r.Context(), tx, groupID)
	if err != nil {
		scimError(w, 500, "delete failed")
		return
	}
	tag, err := tx.Exec(r.Context(), `DELETE FROM scim_groups WHERE id=$1 AND organization_id=$2`, groupID, orgID)
	if err != nil || tag.RowsAffected() == 0 {
		scimError(w, 404, "group not found")
		return
	}
	for _, userID := range users {
		if err = reconcileSCIMRole(r.Context(), tx, orgID, userID); err != nil {
			scimError(w, 500, "role reconciliation failed")
			return
		}
	}
	if err = s.Store.AuditOrganizationTx(r.Context(), tx, orgID, "scim.group.delete", "scim_group", groupID.String(), r.RemoteAddr, nil); err != nil {
		scimError(w, 500, "delete failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		scimError(w, 500, "delete failed")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) loadSCIMGroup(ctx context.Context, orgID, groupID uuid.UUID) (scimGroupResponse, error) {
	item := scimGroupResponse{Schemas: []string{scimGroupSchema}, ID: groupID.String(), Members: []scimMember{}, Meta: map[string]string{"resourceType": "Group", "location": s.PublicURL + "/scim/v2/Groups/" + groupID.String()}}
	var externalID *string
	if err := s.Store.Pool.QueryRow(ctx, `SELECT external_id,display_name,role FROM scim_groups WHERE id=$1 AND organization_id=$2`, groupID, orgID).Scan(&externalID, &item.DisplayName, &item.Role); err != nil {
		return scimGroupResponse{}, err
	}
	if externalID != nil {
		item.ExternalID = *externalID
	}
	rows, err := s.Store.Pool.Query(ctx, `SELECT u.id,u.email FROM scim_group_members gm JOIN users u ON u.id=gm.user_id WHERE gm.group_id=$1 ORDER BY u.email`, groupID)
	if err != nil {
		return scimGroupResponse{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var email string
		if err = rows.Scan(&id, &email); err != nil {
			return scimGroupResponse{}, err
		}
		item.Members = append(item.Members, scimMember{Value: id.String(), Display: email})
	}
	return item, rows.Err()
}

func replaceSCIMMembers(ctx context.Context, tx pgx.Tx, orgID, groupID uuid.UUID, members []scimMember) error {
	old, err := groupUserIDs(ctx, tx, groupID)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM scim_group_members WHERE group_id=$1`, groupID); err != nil {
		return err
	}
	if err = addSCIMMembers(ctx, tx, orgID, groupID, members); err != nil {
		return err
	}
	for _, id := range old {
		if err = reconcileSCIMRole(ctx, tx, orgID, id); err != nil {
			return err
		}
	}
	return nil
}

func addSCIMMembers(ctx context.Context, tx pgx.Tx, orgID, groupID uuid.UUID, members []scimMember) error {
	for _, member := range members {
		userID, err := uuid.Parse(member.Value)
		if err != nil {
			return errors.New("member value must be a user UUID")
		}
		var allowed bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2)`, orgID, userID).Scan(&allowed); err != nil {
			return err
		}
		if !allowed {
			return errors.New("group member is not in the organization")
		}
		if _, err = tx.Exec(ctx, `INSERT INTO scim_group_members(group_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, groupID, userID); err != nil {
			return err
		}
		if err = reconcileSCIMRole(ctx, tx, orgID, userID); err != nil {
			return err
		}
	}
	return nil
}

func removeSCIMMembers(ctx context.Context, tx pgx.Tx, orgID, groupID uuid.UUID, members []scimMember) error {
	for _, member := range members {
		userID, err := uuid.Parse(member.Value)
		if err != nil {
			return errors.New("member value must be a user UUID")
		}
		if _, err = tx.Exec(ctx, `DELETE FROM scim_group_members WHERE group_id=$1 AND user_id=$2`, groupID, userID); err != nil {
			return err
		}
		if err = reconcileSCIMRole(ctx, tx, orgID, userID); err != nil {
			return err
		}
	}
	return nil
}

func groupUserIDs(ctx context.Context, tx pgx.Tx, groupID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT user_id FROM scim_group_members WHERE group_id=$1`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func reconcileSCIMRole(ctx context.Context, tx pgx.Tx, orgID, userID uuid.UUID) error {
	var role string
	err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT g.role FROM scim_group_members gm JOIN scim_groups g ON g.id=gm.group_id WHERE g.organization_id=$1 AND gm.user_id=$2 ORDER BY CASE g.role WHEN 'admin' THEN 3 WHEN 'developer' THEN 2 ELSE 1 END DESC LIMIT 1),(SELECT default_role FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2),'viewer')`, orgID, userID).Scan(&role)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE memberships SET role=$3 WHERE organization_id=$1 AND user_id=$2 AND role<>'owner'`, orgID, userID, role)
	return err
}

func validSCIMRole(role string) bool {
	return role == "admin" || role == "developer" || role == "viewer"
}
