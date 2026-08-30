package store

import (
	"context"
	"testing"
	"time"
)

func TestCredentialPruneResultTotal(t *testing.T) {
	result := CredentialPruneResult{
		Sessions: 1, ServiceAccountTokens: 2, SCIMTokens: 3,
		DeployTokens: 4, Invitations: 5, ClusterEnrollmentTokens: 6,
		OIDCStates: 7, SAMLStates: 8, SAMLAssertions: 9,
	}
	if got := result.Total(); got != 45 {
		t.Fatalf("Total() = %d, want 45", got)
	}
}

func TestPruneExpiredCredentialsRejectsUnsafeRetention(t *testing.T) {
	store := &Store{}
	for _, retention := range []time.Duration{0, 23 * time.Hour, 366 * 24 * time.Hour} {
		if _, err := store.PruneExpiredCredentials(context.Background(), retention); err == nil {
			t.Fatalf("PruneExpiredCredentials(%s) unexpectedly succeeded", retention)
		}
	}
}
