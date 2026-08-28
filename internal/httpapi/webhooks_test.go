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
	githubBody := []byte(`{"ref":"refs/heads/main","deleted":false}`)
	githubHeader := http.Header{"X-Hub-Signature-256": {testWebhookSignature(secret, githubBody)}, "X-Github-Delivery": {"delivery-1"}, "X-Github-Event": {"push"}}
	delivery, branches, err := verifyProviderWebhook("github", secret, githubHeader, githubBody)
	if err != nil || delivery != "delivery-1" || len(branches) != 1 || branches[0] != "refs/heads/main" {
		t.Fatalf("github result = %q/%q, err = %v", delivery, branches, err)
	}
	githubHeader.Set("X-Hub-Signature-256", testWebhookSignature(secret, []byte("tampered")))
	if _, _, err = verifyProviderWebhook("github", secret, githubHeader, githubBody); err == nil {
		t.Fatal("tampered GitHub payload was accepted")
	}

	gitlabHeader := http.Header{"X-Gitlab-Token": {secret}, "X-Gitlab-Event-Uuid": {"delivery-2"}, "X-Gitlab-Event": {"Push Hook"}}
	if delivery, branches, err = verifyProviderWebhook("gitlab", secret, gitlabHeader, []byte(`{"ref":"refs/heads/release"}`)); err != nil || delivery != "delivery-2" || len(branches) != 1 || branches[0] != "refs/heads/release" {
		t.Fatalf("gitlab result = %q/%q, err = %v", delivery, branches, err)
	}

	bitbucketBody := []byte(`{"push":{"changes":[{"new":{"name":"main","type":"branch"}}]}}`)
	bitbucketHeader := http.Header{"X-Hub-Signature": {testWebhookSignature(secret, bitbucketBody)}, "X-Request-Uuid": {"delivery-3"}, "X-Event-Key": {"repo:push"}}
	if delivery, branches, err = verifyProviderWebhook("bitbucket", secret, bitbucketHeader, bitbucketBody); err != nil || delivery != "delivery-3" || len(branches) != 1 || branches[0] != "main" {
		t.Fatalf("bitbucket result = %q/%q, err = %v", delivery, branches, err)
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
