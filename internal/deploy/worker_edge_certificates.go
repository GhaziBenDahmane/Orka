package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/clustercontract"
	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (w *Worker) reconcileEdgeCertificates(ctx context.Context, job job) error {
	var payload struct {
		TargetKey string `json:"targetKey"`
	}
	if json.Unmarshal(job.Payload, &payload) != nil || payload.TargetKey == "" {
		return errors.New("invalid edge certificate reconciliation payload")
	}
	target, err := w.Store.GetEdgeCertificateTarget(ctx, payload.TargetKey)
	if err != nil {
		return err
	}
	proxy, err := w.edgeProxyForTarget(ctx, target)
	if err != nil {
		w.recordEdgeCertificateFailure(ctx, job, target, err)
		return err
	}
	certificates, err := w.Store.ListDesiredEdgeCertificates(ctx, target)
	if err != nil {
		return err
	}
	materials := make([]EdgeCertificateMaterial, 0, len(certificates))
	for _, certificate := range certificates {
		certificatePEM, decryptErr := w.Box.Decrypt(certificate.EncryptedCertificate, cryptox.ResourceContext("custom-tls-certificate-certificate", certificate.ID.String()))
		if decryptErr != nil {
			err = fmt.Errorf("decrypt certificate %s: %w", certificate.ID, decryptErr)
			break
		}
		privateKeyPEM, decryptErr := w.Box.Decrypt(certificate.EncryptedPrivateKey, cryptox.ResourceContext("custom-tls-certificate-private-key", certificate.ID.String()))
		if decryptErr != nil {
			clear(certificatePEM)
			err = fmt.Errorf("decrypt private key for certificate %s: %w", certificate.ID, decryptErr)
			break
		}
		materials = append(materials, EdgeCertificateMaterial{ID: certificate.ID, Revision: certificate.Revision, Fingerprint: certificate.Fingerprint, CertificatePEM: string(certificatePEM), PrivateKeyPEM: string(privateKeyPEM)})
		clear(certificatePEM)
		clear(privateKeyPEM)
	}
	if err == nil {
		manager, ok := w.scheduler(target.ClusterID).(EdgeCertificateManager)
		if !ok {
			err = errors.New("scheduler does not support edge certificates")
		} else {
			err = manager.ReconcileEdgeCertificates(ctx, proxy, materials)
		}
	}
	for index := range materials {
		materials[index].CertificatePEM = ""
		materials[index].PrivateKeyPEM = ""
	}
	if err != nil {
		w.recordEdgeCertificateFailure(context.WithoutCancel(ctx), job, target, err)
		return err
	}
	return w.updateResourceForJob(ctx, job, `UPDATE edge_certificate_targets SET applied_generation=$2,status=CASE WHEN generation=$2 THEN 'ready' ELSE 'pending' END,last_error='',affected_organization_ids=CASE WHEN generation=$2 THEN '{}'::uuid[] ELSE affected_organization_ids END,updated_at=now() WHERE target_key=$1`, target.TargetKey, target.Generation)
}

func (w *Worker) edgeProxyForTarget(ctx context.Context, target store.EdgeCertificateTarget) (EdgeProxySpec, error) {
	if target.ClusterID == nil {
		if !safeRuntimeServiceName.MatchString(w.LocalEdgeProxy.ServiceName) || !validDynamicConfigurationPath(w.LocalEdgeProxy.DynamicConfigurationPath) {
			return EdgeProxySpec{}, errors.New("local edge proxy contract is not configured")
		}
		return w.LocalEdgeProxy, nil
	}
	var raw []byte
	if err := w.Store.Pool.QueryRow(ctx, `SELECT capabilities FROM clusters WHERE id=$1 AND state='active' AND last_seen_at>now()-interval '2 minutes'`, *target.ClusterID).Scan(&raw); errors.Is(err, pgx.ErrNoRows) {
		return EdgeProxySpec{}, store.ErrClusterUnavailable
	} else if err != nil {
		return EdgeProxySpec{}, err
	}
	var capabilities clustercontract.Capabilities
	if json.Unmarshal(raw, &capabilities) != nil || clustercontract.Validate(capabilities) != nil || capabilities.EdgeProxy == nil || !capabilities.EdgeProxy.Ready || !capabilities.EdgeProxy.SupportsCustomCertificates {
		return EdgeProxySpec{}, errors.New("remote cluster does not report a ready custom-certificate edge proxy")
	}
	return EdgeProxySpec{ServiceName: capabilities.EdgeProxy.ServiceName, DynamicConfigurationPath: capabilities.EdgeProxy.DynamicConfigurationPath}, nil
}

func (w *Worker) recordEdgeCertificateFailure(ctx context.Context, job job, target store.EdgeCertificateTarget, reconcileErr error) {
	status := "pending"
	if job.Attempts+1 >= job.MaxAttempts {
		status = "error"
	}
	_ = w.updateResourceForJob(ctx, job, `UPDATE edge_certificate_targets SET status=$2,last_error=$3,updated_at=now() WHERE target_key=$1`, target.TargetKey, status, truncate(reconcileErr.Error(), 2048))
}

func (w *Worker) waitForEdgeCertificates(ctx context.Context, clusterID *uuid.UUID, timeout time.Duration) error {
	targetKey := "local"
	if clusterID != nil {
		targetKey = clusterID.String()
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		target, err := w.Store.GetEdgeCertificateTarget(ctx, targetKey)
		if err == nil && target.Status == "ready" && target.AppliedGeneration == target.Generation {
			return nil
		}
		if err == nil && target.Status == "error" {
			return fmt.Errorf("custom TLS certificate reconciliation failed: %s", target.LastError)
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("custom TLS certificates were not reconciled before deployment")
		case <-ticker.C:
		}
	}
}
