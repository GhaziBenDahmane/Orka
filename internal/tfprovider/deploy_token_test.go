package tfprovider

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestDeployTokenSecretsAreSensitive(t *testing.T) {
	var response resource.SchemaResponse
	newDeployTokenResource().Schema(context.Background(), resource.SchemaRequest{}, &response)
	for _, name := range []string{"token", "url"} {
		attribute, ok := response.Schema.Attributes[name].(resourceschema.StringAttribute)
		if !ok || !attribute.Sensitive || !attribute.Computed {
			t.Fatalf("%s schema = %#v", name, response.Schema.Attributes[name])
		}
	}
}

func TestDeployTokenWindowValidation(t *testing.T) {
	for _, test := range []struct {
		expires, renew int64
		wantAttribute  string
	}{
		{0, 0, "expires_in_days"},
		{366, 1, "expires_in_days"},
		{30, -1, "renew_before_days"},
		{30, 30, "renew_before_days"},
		{30, 7, ""},
	} {
		attribute, err := validateDeployTokenWindow(test.expires, test.renew)
		if attribute != test.wantAttribute || (err != nil) != (test.wantAttribute != "") {
			t.Fatalf("validateDeployTokenWindow(%d, %d) = %q, %v", test.expires, test.renew, attribute, err)
		}
	}
}

func TestDeployTokenRenewalAndSecretRetention(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	model := deployTokenModel{Token: types.StringValue("one-time-token"), URL: types.StringValue("https://orka.example/v1/hooks/deploy/one-time-token")}
	setDeployToken(&model, deployTokenResponse{ID: "token-id", ComposeServiceID: "service-id", Name: "ci-release", CreatedAt: now.Add(-24 * time.Hour).Format(time.RFC3339Nano), ExpiresAt: now.Add(8 * 24 * time.Hour).Format(time.RFC3339Nano)})
	if model.Token.ValueString() != "one-time-token" || model.URL.ValueString() == "" {
		t.Fatalf("refresh discarded write-only values: %#v", model)
	}
	if renew, err := deployTokenRequiresRenewal(model.ExpiresAt, now, 7); err != nil || renew {
		t.Fatalf("unexpected early renewal: renew=%t err=%v", renew, err)
	}
	model.ExpiresAt = types.StringValue(now.Add(7 * 24 * time.Hour).Format(time.RFC3339Nano))
	if renew, err := deployTokenRequiresRenewal(model.ExpiresAt, now, 7); err != nil || !renew {
		t.Fatalf("expected renewal at boundary: renew=%t err=%v", renew, err)
	}
}

func TestUsableDeployTokenRejectsRevokedExpiredAndMalformed(t *testing.T) {
	now := time.Now().UTC()
	revoked := now.Add(-time.Minute).Format(time.RFC3339Nano)
	for _, test := range []struct {
		name string
		item deployTokenResponse
		want bool
		err  bool
	}{
		{"active", deployTokenResponse{ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}, true, false},
		{"expired", deployTokenResponse{ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339Nano)}, false, false},
		{"revoked", deployTokenResponse{ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), RevokedAt: &revoked}, false, false},
		{"malformed", deployTokenResponse{ExpiresAt: "not-a-time"}, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			usable, err := usableDeployToken(test.item, now)
			if usable != test.want || (err != nil) != test.err {
				t.Fatalf("usable=%t err=%v", usable, err)
			}
		})
	}
}
