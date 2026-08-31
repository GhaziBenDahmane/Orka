package store

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CustomTLSCertificate struct {
	ID                   uuid.UUID `json:"id"`
	OrganizationID       uuid.UUID `json:"organizationId"`
	Name                 string    `json:"name"`
	EncryptedCertificate string    `json:"-"`
	EncryptedPrivateKey  string    `json:"-"`
	Fingerprint          string    `json:"fingerprint"`
	CommonName           string    `json:"commonName"`
	DNSNames             []string  `json:"dnsNames"`
	NotBefore            time.Time `json:"notBefore"`
	NotAfter             time.Time `json:"notAfter"`
	Revision             int64     `json:"revision"`
	CreatedAt            time.Time `json:"createdAt"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

type EdgeCertificateTarget struct {
	TargetKey         string
	ClusterID         *uuid.UUID
	Generation        int64
	AppliedGeneration int64
	Status            string
	LastError         string
}

const customTLSCertificateColumns = `id,organization_id,name,encrypted_certificate,encrypted_private_key,fingerprint,common_name,dns_names,not_before,not_after,revision,created_at,updated_at`

func scanCustomTLSCertificate(row pgx.Row) (CustomTLSCertificate, error) {
	var item CustomTLSCertificate
	err := row.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.EncryptedCertificate, &item.EncryptedPrivateKey, &item.Fingerprint, &item.CommonName, &item.DNSNames, &item.NotBefore, &item.NotAfter, &item.Revision, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Store) CreateCustomTLSCertificate(ctx context.Context, item CustomTLSCertificate) (CustomTLSCertificate, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return CustomTLSCertificate{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createCustomTLSCertificateTx(ctx, tx, item)
	if err != nil {
		return CustomTLSCertificate{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) CreateCustomTLSCertificateWithAudit(ctx context.Context, principal Principal, item CustomTLSCertificate, remoteAddr string) (CustomTLSCertificate, error) {
	item.OrganizationID = principal.OrganizationID
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return CustomTLSCertificate{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createCustomTLSCertificateTx(ctx, tx, item)
	if err != nil {
		return CustomTLSCertificate{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "custom_tls_certificate.create", "custom_tls_certificate", item.ID.String(), remoteAddr, map[string]any{"fingerprint": item.Fingerprint, "notAfter": item.NotAfter}); err != nil {
		return CustomTLSCertificate{}, err
	}
	return item, tx.Commit(ctx)
}

func createCustomTLSCertificateTx(ctx context.Context, tx pgx.Tx, item CustomTLSCertificate) (CustomTLSCertificate, error) {
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	item.Revision = 1
	item, err := scanCustomTLSCertificate(tx.QueryRow(ctx, `INSERT INTO custom_tls_certificates(id,organization_id,name,encrypted_certificate,encrypted_private_key,fingerprint,common_name,dns_names,not_before,not_after) SELECT $1,o.id,$3,$4,$5,$6,$7,$8,$9,$10 FROM organizations o WHERE o.id=$2 RETURNING `+customTLSCertificateColumns, item.ID, item.OrganizationID, item.Name, item.EncryptedCertificate, item.EncryptedPrivateKey, item.Fingerprint, item.CommonName, item.DNSNames, item.NotBefore, item.NotAfter))
	if errors.Is(err, pgx.ErrNoRows) {
		return CustomTLSCertificate{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListCustomTLSCertificates(ctx context.Context, organizationID uuid.UUID) ([]CustomTLSCertificate, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+customTLSCertificateColumns+` FROM custom_tls_certificates WHERE organization_id=$1 ORDER BY lower(name),id`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []CustomTLSCertificate{}
	for rows.Next() {
		item, scanErr := scanCustomTLSCertificate(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetCustomTLSCertificate(ctx context.Context, organizationID, id uuid.UUID) (CustomTLSCertificate, error) {
	item, err := scanCustomTLSCertificate(s.Pool.QueryRow(ctx, `SELECT `+customTLSCertificateColumns+` FROM custom_tls_certificates WHERE id=$1 AND organization_id=$2`, id, organizationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return CustomTLSCertificate{}, ErrNotFound
	}
	return item, err
}

func (s *Store) UpdateCustomTLSCertificate(ctx context.Context, item CustomTLSCertificate) (CustomTLSCertificate, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return CustomTLSCertificate{}, err
	}
	defer tx.Rollback(ctx)
	item, err = updateCustomTLSCertificateTx(ctx, tx, item)
	if err != nil {
		return CustomTLSCertificate{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) UpdateCustomTLSCertificateWithAudit(ctx context.Context, principal Principal, item CustomTLSCertificate, remoteAddr string) (CustomTLSCertificate, error) {
	item.OrganizationID = principal.OrganizationID
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return CustomTLSCertificate{}, err
	}
	defer tx.Rollback(ctx)
	item, err = updateCustomTLSCertificateTx(ctx, tx, item)
	if err != nil {
		return CustomTLSCertificate{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "custom_tls_certificate.rotate", "custom_tls_certificate", item.ID.String(), remoteAddr, map[string]any{"fingerprint": item.Fingerprint, "notAfter": item.NotAfter, "revision": item.Revision}); err != nil {
		return CustomTLSCertificate{}, err
	}
	return item, tx.Commit(ctx)
}

func updateCustomTLSCertificateTx(ctx context.Context, tx pgx.Tx, item CustomTLSCertificate) (CustomTLSCertificate, error) {
	var err error
	item, err = scanCustomTLSCertificate(tx.QueryRow(ctx, `UPDATE custom_tls_certificates SET name=$3,encrypted_certificate=$4,encrypted_private_key=$5,fingerprint=$6,common_name=$7,dns_names=$8,not_before=$9,not_after=$10,revision=revision+1,updated_at=now() WHERE id=$1 AND organization_id=$2 AND revision=$11 RETURNING `+customTLSCertificateColumns, item.ID, item.OrganizationID, item.Name, item.EncryptedCertificate, item.EncryptedPrivateKey, item.Fingerprint, item.CommonName, item.DNSNames, item.NotBefore, item.NotAfter, item.Revision))
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if checkErr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM custom_tls_certificates WHERE id=$1 AND organization_id=$2)`, item.ID, item.OrganizationID).Scan(&exists); checkErr != nil {
			return CustomTLSCertificate{}, checkErr
		}
		if exists {
			return CustomTLSCertificate{}, ErrRevisionConflict
		}
		return CustomTLSCertificate{}, ErrNotFound
	}
	if err != nil {
		return CustomTLSCertificate{}, err
	}
	if err = queueCertificateTargetsForCertificateTx(ctx, tx, item.ID); err != nil {
		return CustomTLSCertificate{}, err
	}
	return item, nil
}

func (s *Store) DeleteCustomTLSCertificate(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteCustomTLSCertificateTx(ctx, tx, organizationID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteCustomTLSCertificateWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteCustomTLSCertificateTx(ctx, tx, principal.OrganizationID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "custom_tls_certificate.delete", "custom_tls_certificate", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func deleteCustomTLSCertificateTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	tag, err := tx.Exec(ctx, `DELETE FROM custom_tls_certificates certificate WHERE certificate.id=$1 AND certificate.organization_id=$2 AND NOT EXISTS(SELECT 1 FROM routes WHERE custom_certificate_id=certificate.id)`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM custom_tls_certificates WHERE id=$1 AND organization_id=$2)`, id, organizationID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrBusy
		}
		return ErrNotFound
	}
	return nil
}

func queueCertificateTargetsForCertificateTx(ctx context.Context, tx pgx.Tx, certificateID uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT environment.cluster_id FROM routes route JOIN compose_services service ON service.id=route.compose_service_id JOIN environments environment ON environment.id=service.environment_id WHERE route.custom_certificate_id=$1`, certificateID)
	if err != nil {
		return err
	}
	var targets []*uuid.UUID
	for rows.Next() {
		var clusterID *uuid.UUID
		if err = rows.Scan(&clusterID); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, clusterID)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, clusterID := range targets {
		if err = queueEdgeCertificateReconciliationTx(ctx, tx, clusterID); err != nil {
			return err
		}
	}
	return nil
}

func queueEdgeCertificateReconciliationTx(ctx context.Context, tx pgx.Tx, clusterID *uuid.UUID) error {
	targetKey := "local"
	if clusterID != nil {
		targetKey = clusterID.String()
	}
	if _, err := tx.Exec(ctx, `INSERT INTO edge_certificate_targets(target_key,cluster_id) VALUES($1,$2) ON CONFLICT(target_key) DO UPDATE SET generation=edge_certificate_targets.generation+1,status='pending',last_error='',updated_at=now()`, targetKey, clusterID); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"targetKey": targetKey})
	_, err := tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,max_attempts) SELECT $1,'edge-certificates.reconcile',$2,$3,10 WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE kind='edge-certificates.reconcile' AND payload->>'targetKey'=$4 AND status='pending')`, uuid.New(), payload, "edge-certificates:"+targetKey, targetKey)
	return err
}

func queueEdgeCertificateReconciliationForEnvironmentTx(ctx context.Context, tx pgx.Tx, environmentID uuid.UUID) error {
	var clusterID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT cluster_id FROM environments WHERE id=$1`, environmentID).Scan(&clusterID); err != nil {
		return err
	}
	return queueEdgeCertificateReconciliationTx(ctx, tx, clusterID)
}

func (s *Store) GetEdgeCertificateTarget(ctx context.Context, targetKey string) (EdgeCertificateTarget, error) {
	var target EdgeCertificateTarget
	err := s.Pool.QueryRow(ctx, `SELECT target_key,cluster_id,generation,applied_generation,status,last_error FROM edge_certificate_targets WHERE target_key=$1`, targetKey).Scan(&target.TargetKey, &target.ClusterID, &target.Generation, &target.AppliedGeneration, &target.Status, &target.LastError)
	if errors.Is(err, pgx.ErrNoRows) {
		return EdgeCertificateTarget{}, ErrNotFound
	}
	return target, err
}

func (s *Store) QueueAllEdgeCertificateReconciliations(ctx context.Context) (int, error) {
	tag, err := s.Pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,max_attempts)
		SELECT gen_random_uuid(),'edge-certificates.reconcile',jsonb_build_object('targetKey',target.target_key),'edge-certificates:' || target.target_key,10
		FROM edge_certificate_targets target
		WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE kind='edge-certificates.reconcile' AND payload->>'targetKey'=target.target_key AND status IN ('pending','running'))`)
	return int(tag.RowsAffected()), err
}

func (s *Store) ListDesiredEdgeCertificates(ctx context.Context, target EdgeCertificateTarget) ([]CustomTLSCertificate, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT `+stringsWithPrefix(customTLSCertificateColumns, "certificate.")+`
		FROM custom_tls_certificates certificate
		JOIN routes route ON route.custom_certificate_id=certificate.id
		JOIN compose_services service ON service.id=route.compose_service_id
		JOIN environments environment ON environment.id=service.environment_id
		WHERE route.enabled AND route.tls AND (($1::uuid IS NULL AND environment.cluster_id IS NULL) OR environment.cluster_id=$1)
		ORDER BY certificate.id`, target.ClusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []CustomTLSCertificate{}
	for rows.Next() {
		item, scanErr := scanCustomTLSCertificate(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func stringsWithPrefix(columns, prefix string) string {
	parts := strings.Split(columns, ",")
	for index := range parts {
		parts[index] = prefix + parts[index]
	}
	return strings.Join(parts, ",")
}

func validateRouteCertificateTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, certificateID *uuid.UUID, hostname string) error {
	if certificateID == nil {
		return nil
	}
	var dnsNames []string
	err := tx.QueryRow(ctx, `SELECT dns_names FROM custom_tls_certificates WHERE id=$1 AND organization_id=$2 AND not_before<=now()+interval '5 minutes' AND not_after>now()+interval '24 hours'`, *certificateID, organizationID).Scan(&dnsNames)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidRouteCertificate
	}
	if err != nil {
		return err
	}
	certificate := x509.Certificate{DNSNames: dnsNames}
	if certificate.VerifyHostname(hostname) != nil {
		return ErrInvalidRouteCertificate
	}
	return nil
}
