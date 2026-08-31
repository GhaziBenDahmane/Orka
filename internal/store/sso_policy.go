package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// setSSOProviderEnabled serializes provider changes with the organization SSO
// policy. The organization row is the shared lock across OIDC and SAML, so two
// concurrent disables cannot each observe the other provider as enabled.
func (s *Store) setSSOProviderEnabled(ctx context.Context, organizationID, providerID uuid.UUID, kind string, enabled bool) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = setSSOProviderEnabledTx(ctx, tx, organizationID, providerID, kind, enabled); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) SetSSOProviderEnabledWithAudit(ctx context.Context, principal Principal, providerID uuid.UUID, kind string, enabled bool, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = setSSOProviderEnabledTx(ctx, tx, principal.OrganizationID, providerID, kind, enabled); err != nil {
		return err
	}
	resourceType := kind + "_provider"
	action := "sso." + kind + ".disable"
	if enabled {
		action = "sso." + kind + ".enable"
	}
	if err = appendPrincipalAudit(ctx, tx, principal, action, resourceType, providerID.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func setSSOProviderEnabledTx(ctx context.Context, tx pgx.Tx, organizationID, providerID uuid.UUID, kind string, enabled bool) error {
	table := "oidc_providers"
	if kind == "saml" {
		table = "saml_providers"
	} else if kind != "oidc" {
		return errors.New("invalid SSO provider kind")
	}
	var organizationExists bool
	if err := tx.QueryRow(ctx, `SELECT true FROM organizations WHERE id=$1 FOR UPDATE`, organizationID).Scan(&organizationExists); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	var currentlyEnabled bool
	if err := tx.QueryRow(ctx, `SELECT enabled FROM `+table+` WHERE id=$1 AND organization_id=$2 FOR UPDATE`, providerID, organizationID).Scan(&currentlyEnabled); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if !enabled && currentlyEnabled {
		var requireSSO bool
		var enabledProviders int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT require_sso FROM organization_auth_settings WHERE organization_id=$1),false),
			(SELECT count(*) FROM oidc_providers WHERE organization_id=$1 AND enabled) +
			(SELECT count(*) FROM saml_providers WHERE organization_id=$1 AND enabled)`, organizationID).Scan(&requireSSO, &enabledProviders); err != nil {
			return err
		}
		if requireSSO && enabledProviders <= 1 {
			return ErrSSOProviderRequired
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE `+table+` SET enabled=$3,revision=CASE WHEN enabled<>$3 THEN revision+1 ELSE revision END WHERE id=$1 AND organization_id=$2`, providerID, organizationID, enabled); err != nil {
		return err
	}
	if enabled != currentlyEnabled {
		stateTable := "oidc_states"
		providerColumn := "oidc_provider_id"
		if kind == "saml" {
			stateTable = "saml_states"
			providerColumn = "saml_provider_id"
		}
		// A provider state transition is an authentication trust-boundary
		// change. Revoke every outstanding browser flow so a login started
		// before a disable (or while configuration was being reviewed) cannot
		// become valid again after the provider is enabled.
		if _, err := tx.Exec(ctx, `DELETE FROM `+stateTable+` WHERE provider_id=$1`, providerID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE `+providerColumn+`=$1`, providerID); err != nil {
			return err
		}
	}
	return nil
}
