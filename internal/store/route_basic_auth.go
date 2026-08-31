package store

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

type RouteBasicAuthUser struct {
	ID               uuid.UUID `json:"id"`
	ComposeServiceID uuid.UUID `json:"composeServiceId"`
	Username         string    `json:"username"`
	PasswordHash     string    `json:"-"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

func validateRouteBasicAuth(username, password string, passwordRequired bool) error {
	if username != strings.TrimSpace(username) || username == "" || len(username) > 128 || !utf8.ValidString(username) || strings.ContainsAny(username, ",:\r\n\x00") {
		return errors.Join(ErrInvalidRouteBasicAuth, errors.New("username must be 1-128 UTF-8 characters without comma, colon, or control separators"))
	}
	if (passwordRequired || password != "") && (password == "" || len(password) > 72 || !utf8.ValidString(password) || strings.ContainsRune(password, 0)) {
		return errors.Join(ErrInvalidRouteBasicAuth, errors.New("password must be 1-72 valid UTF-8 bytes"))
	}
	return nil
}

func scanRouteBasicAuthUser(row pgx.Row) (RouteBasicAuthUser, error) {
	var item RouteBasicAuthUser
	err := row.Scan(&item.ID, &item.ComposeServiceID, &item.Username, &item.PasswordHash, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Store) ListRouteBasicAuthUsers(ctx context.Context, organizationID, serviceID uuid.UUID) ([]RouteBasicAuthUser, error) {
	rows, err := s.Pool.Query(ctx, `SELECT auth.id,auth.compose_service_id,auth.username,auth.password_hash,auth.created_at,auth.updated_at FROM route_basic_auth_users auth JOIN compose_services service ON service.id=auth.compose_service_id JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE auth.compose_service_id=$1 AND project.organization_id=$2 ORDER BY auth.username,auth.id`, serviceID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []RouteBasicAuthUser{}
	for rows.Next() {
		item, scanErr := scanRouteBasicAuthUser(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CreateRouteBasicAuthUser(ctx context.Context, organizationID, serviceID uuid.UUID, username, password string) (RouteBasicAuthUser, error) {
	if err := validateRouteBasicAuth(username, password, true); err != nil {
		return RouteBasicAuthUser{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	defer tx.Rollback(ctx)
	item, err := s.createRouteBasicAuthUserTx(ctx, tx, organizationID, serviceID, username, string(hash))
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) CreateRouteBasicAuthUserWithAudit(ctx context.Context, principal Principal, serviceID uuid.UUID, username, password, remoteAddr string) (RouteBasicAuthUser, error) {
	if err := validateRouteBasicAuth(username, password, true); err != nil {
		return RouteBasicAuthUser{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	defer tx.Rollback(ctx)
	item, err := s.createRouteBasicAuthUserTx(ctx, tx, principal.OrganizationID, serviceID, username, string(hash))
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "route_basic_auth.create", "service", serviceID.String(), remoteAddr, map[string]any{"username": item.Username}); err != nil {
		return RouteBasicAuthUser{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) createRouteBasicAuthUserTx(ctx context.Context, tx pgx.Tx, organizationID, serviceID uuid.UUID, username, passwordHash string) (RouteBasicAuthUser, error) {
	projectID, environmentID, err := lockActiveServiceForMutation(ctx, tx, organizationID, serviceID)
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return RouteBasicAuthUser{}, err
	}
	if err := ensureNoActiveDeploymentTx(ctx, tx, serviceID); err != nil {
		return RouteBasicAuthUser{}, err
	}
	item := RouteBasicAuthUser{ID: uuid.New(), ComposeServiceID: serviceID, Username: username, PasswordHash: passwordHash}
	item, err = scanRouteBasicAuthUser(tx.QueryRow(ctx, `INSERT INTO route_basic_auth_users(id,compose_service_id,username,password_hash) VALUES($1,$2,$3,$4) RETURNING id,compose_service_id,username,password_hash,created_at,updated_at`, item.ID, serviceID, username, item.PasswordHash))
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	return item, nil
}

func (s *Store) UpdateRouteBasicAuthUser(ctx context.Context, organizationID, serviceID, id uuid.UUID, username, password string) (RouteBasicAuthUser, error) {
	if err := validateRouteBasicAuth(username, password, false); err != nil {
		return RouteBasicAuthUser{}, err
	}
	passwordHash := ""
	if password != "" {
		encoded, err := bcrypt.GenerateFromPassword([]byte(password), 12)
		if err != nil {
			return RouteBasicAuthUser{}, err
		}
		passwordHash = string(encoded)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	defer tx.Rollback(ctx)
	item, err := s.updateRouteBasicAuthUserTx(ctx, tx, organizationID, serviceID, id, username, passwordHash)
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) UpdateRouteBasicAuthUserWithAudit(ctx context.Context, principal Principal, serviceID, id uuid.UUID, username, password, remoteAddr string) (RouteBasicAuthUser, error) {
	if err := validateRouteBasicAuth(username, password, false); err != nil {
		return RouteBasicAuthUser{}, err
	}
	passwordHash := ""
	if password != "" {
		encoded, err := bcrypt.GenerateFromPassword([]byte(password), 12)
		if err != nil {
			return RouteBasicAuthUser{}, err
		}
		passwordHash = string(encoded)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	defer tx.Rollback(ctx)
	item, err := s.updateRouteBasicAuthUserTx(ctx, tx, principal.OrganizationID, serviceID, id, username, passwordHash)
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "route_basic_auth.update", "service", serviceID.String(), remoteAddr, map[string]any{"username": item.Username}); err != nil {
		return RouteBasicAuthUser{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) updateRouteBasicAuthUserTx(ctx context.Context, tx pgx.Tx, organizationID, serviceID, id uuid.UUID, username, passwordHash string) (RouteBasicAuthUser, error) {
	projectID, environmentID, err := lockActiveServiceForMutation(ctx, tx, organizationID, serviceID)
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return RouteBasicAuthUser{}, err
	}
	if err = ensureNoActiveDeploymentTx(ctx, tx, serviceID); err != nil {
		return RouteBasicAuthUser{}, err
	}
	var hash string
	err = tx.QueryRow(ctx, `SELECT password_hash FROM route_basic_auth_users WHERE id=$1 AND compose_service_id=$2 FOR UPDATE`, id, serviceID).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return RouteBasicAuthUser{}, ErrNotFound
	}
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	if passwordHash != "" {
		hash = passwordHash
	}
	item, err := scanRouteBasicAuthUser(tx.QueryRow(ctx, `UPDATE route_basic_auth_users SET username=$3,password_hash=$4,updated_at=now() WHERE id=$1 AND compose_service_id=$2 RETURNING id,compose_service_id,username,password_hash,created_at,updated_at`, id, serviceID, username, hash))
	if err != nil {
		return RouteBasicAuthUser{}, err
	}
	return item, nil
}

func (s *Store) DeleteRouteBasicAuthUser(ctx context.Context, organizationID, serviceID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = s.deleteRouteBasicAuthUserTx(ctx, tx, organizationID, serviceID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteRouteBasicAuthUserWithAudit(ctx context.Context, principal Principal, serviceID, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = s.deleteRouteBasicAuthUserTx(ctx, tx, principal.OrganizationID, serviceID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "route_basic_auth.delete", "service", serviceID.String(), remoteAddr, map[string]any{"userId": id}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) deleteRouteBasicAuthUserTx(ctx context.Context, tx pgx.Tx, organizationID, serviceID, id uuid.UUID) error {
	if _, _, err := lockActiveServiceForMutation(ctx, tx, organizationID, serviceID); err != nil {
		return err
	}
	if err := ensureNoActiveDeploymentTx(ctx, tx, serviceID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM route_basic_auth_users WHERE id=$1 AND compose_service_id=$2`, id, serviceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
