package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
)

func TestVerifyProviderWebhook(t *testing.T) {
	secret := "test-secret"
	githubBody := []byte(`{"ref":"refs/heads/main","after":"0123456789abcdef0123456789abcdef01234567","deleted":false}`)
	githubHeader := http.Header{"X-Hub-Signature-256": {testWebhookSignature(secret, githubBody)}, "X-Github-Delivery": {"delivery-1"}, "X-Github-Event": {"push"}}
	delivery, refs, err := verifyProviderWebhook("github", secret, githubHeader, githubBody)
	if err != nil || delivery != "delivery-1" || len(refs) != 1 || refs[0].Branch != "refs/heads/main" || refs[0].CommitSHA == "" {
		t.Fatalf("github result = %q/%v, err = %v", delivery, refs, err)
	}
	githubHeader.Set("X-Hub-Signature-256", testWebhookSignature(secret, []byte("tampered")))
	if _, _, err = verifyProviderWebhook("github", secret, githubHeader, githubBody); err == nil {
		t.Fatal("tampered GitHub payload was accepted")
	}

	gitlabHeader := http.Header{"X-Gitlab-Token": {secret}, "X-Gitlab-Event-Uuid": {"delivery-2"}, "X-Gitlab-Event": {"Push Hook"}}
	if delivery, refs, err = verifyProviderWebhook("gitlab", secret, gitlabHeader, []byte(`{"ref":"refs/heads/release","after":"abcdef0123456789abcdef0123456789abcdef01"}`)); err != nil || delivery != "delivery-2" || len(refs) != 1 || refs[0].Branch != "refs/heads/release" {
		t.Fatalf("gitlab result = %q/%v, err = %v", delivery, refs, err)
	}

	bitbucketBody := []byte(`{"push":{"changes":[{"new":{"name":"main","type":"branch","target":{"hash":"abcdef0123456789abcdef0123456789abcdef01"}}}]}}`)
	bitbucketHeader := http.Header{"X-Hub-Signature": {testWebhookSignature(secret, bitbucketBody)}, "X-Request-Uuid": {"delivery-3"}, "X-Event-Key": {"repo:push"}}
	if delivery, refs, err = verifyProviderWebhook("bitbucket", secret, bitbucketHeader, bitbucketBody); err != nil || delivery != "delivery-3" || len(refs) != 1 || refs[0].Branch != "main" {
		t.Fatalf("bitbucket result = %q/%v, err = %v", delivery, refs, err)
	}
	bitbucketHeader.Set("X-Event-Key", "repo:fork")
	if _, _, err = verifyProviderWebhook("bitbucket", secret, bitbucketHeader, bitbucketBody); !errors.Is(err, errWebhookIgnored) {
		t.Fatalf("non-push event error = %v, want ignored", err)
	}
}

func testWebhookSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
