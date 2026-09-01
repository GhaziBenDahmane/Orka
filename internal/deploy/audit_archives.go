package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

type auditArchiveManifest struct {
	Type           string    `json:"type"`
	Version        int       `json:"version"`
	OrganizationID uuid.UUID `json:"organizationId"`
	BatchID        uuid.UUID `json:"batchId"`
	FirstEventID   int64     `json:"firstEventId"`
	LastEventID    int64     `json:"lastEventId"`
	PreviousSHA256 string    `json:"previousSha256"`
	CreatedAt      time.Time `json:"createdAt"`
}

func (w *Worker) archiveAuditEvents(ctx context.Context, j job) error {
	var payload struct {
		BatchID string `json:"batchId"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	id, err := uuid.Parse(payload.BatchID)
	if err != nil {
		return err
	}
	batch, err := w.Store.GetAuditArchiveBatchForJob(ctx, j.ID, j.LeaseID, id)
	if err != nil {
		return err
	}
	events, err := w.Store.ListAuditEvents(ctx, batch.OrganizationID, batch.FirstEventID-1, 1000, true)
	if err != nil {
		return w.failAuditArchive(ctx, j, id, err)
	}
	for len(events) > 0 && events[len(events)-1].ID > batch.LastEventID {
		events = events[:len(events)-1]
	}
	if len(events) == 0 || events[0].ID != batch.FirstEventID || events[len(events)-1].ID != batch.LastEventID {
		return w.failAuditArchive(ctx, j, id, errors.New("audit archive event range is incomplete"))
	}
	contents, digest, err := encodeAuditArchive(batch, events)
	if err != nil {
		return w.failAuditArchive(ctx, j, id, err)
	}
	destination, err := w.s3(ctx, batch.BackupDestination.ID)
	if err == nil {
		err = destination.PutImmutable(ctx, batch.ObjectKey, contents, digest, time.Now().UTC().AddDate(0, 0, batch.RetentionDays))
	}
	if err != nil {
		return w.failAuditArchive(ctx, j, id, err)
	}
	if err = w.Store.FinishAuditArchiveBatchForJob(ctx, j.ID, j.LeaseID, id, digest, int64(len(contents)), nil); err != nil {
		return err
	}
	return nil
}

func encodeAuditArchive(batch store.AuditArchiveBatch, events []store.AuditEvent) ([]byte, string, error) {
	var contents bytes.Buffer
	encoder := json.NewEncoder(&contents)
	manifest := auditArchiveManifest{Type: "dockyard.audit.manifest", Version: 1, OrganizationID: batch.OrganizationID, BatchID: batch.ID, FirstEventID: batch.FirstEventID, LastEventID: batch.LastEventID, PreviousSHA256: batch.PreviousSHA256, CreatedAt: batch.CreatedAt.UTC()}
	if err := encoder.Encode(manifest); err != nil {
		return nil, "", err
	}
	for _, event := range events {
		if event.ID < batch.FirstEventID || event.ID > batch.LastEventID {
			return nil, "", fmt.Errorf("audit event %d is outside batch range", event.ID)
		}
		if err := encoder.Encode(event); err != nil {
			return nil, "", err
		}
	}
	digest := sha256.Sum256(contents.Bytes())
	return contents.Bytes(), hex.EncodeToString(digest[:]), nil
}

func (w *Worker) failAuditArchive(ctx context.Context, j job, id uuid.UUID, archiveErr error) error {
	return errors.Join(archiveErr, w.Store.FinishAuditArchiveBatchForJob(ctx, j.ID, j.LeaseID, id, "", 0, archiveErr))
}
