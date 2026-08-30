package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestLocalTOTPEnrollmentLoginRecoveryAndDisable(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	box, err := cryptox.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	organizationID, secondOrganizationID, userID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	token := "mfa-enrollment-" + uuid.NewString()
	password := "correct-horse-battery-staple"
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'MFA',$2)`, []any{organizationID, "mfa-" + organizationID.String()}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'MFA second',$2)`, []any{secondOrganizationID, "mfa-second-" + secondOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)`, []any{userID, userID.String() + "@example.test", passwordHash}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'viewer')`, []any{secondOrganizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','local')`, []any{sessionID, userID, cryptox.Digest(token)}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id IN ($1,$2)`, organizationID, secondOrganizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	server := httptest.NewServer((&Server{Store: db, Box: box, SessionTTL: time.Hour, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	request := func(path, method string, input any) (int, []byte) {
		return scopedAPIRequest(t, server.URL+path, token, organizationID, method, input)
	}

	status, body := request("/v1/auth/mfa/enrollment", http.MethodPost, map[string]string{"currentPassword": password})
	if status != http.StatusCreated {
		t.Fatalf("begin status=%d body=%s", status, body)
	}
	var enrollment struct{ Secret, OtpauthUri string }
	if err = json.Unmarshal(body, &enrollment); err != nil || enrollment.Secret == "" || !strings.HasPrefix(enrollment.OtpauthUri, "otpauth://") {
		t.Fatalf("invalid enrollment: %s err=%v", body, err)
	}
	var stored string
	if err = db.Pool.QueryRow(ctx, `SELECT pending_encrypted_totp_secret FROM users WHERE id=$1`, userID).Scan(&stored); err != nil || stored == enrollment.Secret || strings.Contains(stored, enrollment.Secret) {
		t.Fatalf("TOTP secret stored in plaintext: err=%v", err)
	}
	code, _ := auth.TOTPCode(enrollment.Secret, time.Now())
	status, body = request("/v1/auth/mfa/enrollment/confirm", http.MethodPost, map[string]string{"code": code})
	if status != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", status, body)
	}
	var confirmed struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	if err = json.Unmarshal(body, &confirmed); err != nil || len(confirmed.RecoveryCodes) != auth.RecoveryCodeCount {
		t.Fatalf("invalid confirmation: %s err=%v", body, err)
	}

	login := func(input map[string]string) (int, []byte) {
		return scopedAPIRequest(t, server.URL+"/v1/auth/login", "", organizationID, http.MethodPost, input)
	}
	base := map[string]string{"email": userID.String() + "@example.test", "password": password}
	if status, body = login(base); status != http.StatusUnauthorized || !strings.Contains(string(body), `"code":"mfa_required"`) {
		t.Fatalf("missing proof status=%d body=%s", status, body)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE users SET encrypted_totp_secret='corrupt' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	base["totpCode"] = code
	if status, body = login(base); status != http.StatusInternalServerError || !strings.Contains(string(body), `"code":"mfa_secret_invalid"`) {
		t.Fatalf("corrupt secret status=%d body=%s", status, body)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE users SET encrypted_totp_secret=$2 WHERE id=$1`, userID, stored); err != nil {
		t.Fatal(err)
	}
	base["totpCode"] = code
	if status, body = login(base); status != http.StatusUnauthorized || !strings.Contains(string(body), `"code":"invalid_mfa"`) {
		t.Fatalf("confirmation-code replay status=%d body=%s", status, body)
	}
	delete(base, "totpCode")
	base["recoveryCode"] = confirmed.RecoveryCodes[0]
	if status, body = login(base); status != http.StatusOK {
		t.Fatalf("recovery login status=%d body=%s", status, body)
	}
	var recoveryLogin struct {
		Token string `json:"token"`
	}
	if err = json.Unmarshal(body, &recoveryLogin); err != nil || recoveryLogin.Token == "" {
		t.Fatalf("recovery login token missing: %s", body)
	}
	if status, body = login(base); status != http.StatusUnauthorized || !strings.Contains(string(body), `"code":"invalid_mfa"`) {
		t.Fatalf("recovery replay status=%d body=%s", status, body)
	}

	status, body = request("/v1/auth/mfa/recovery-codes", http.MethodPost, map[string]string{"currentPassword": password, "recoveryCode": confirmed.RecoveryCodes[1]})
	if status != http.StatusOK {
		t.Fatalf("regenerate status=%d body=%s", status, body)
	}
	var regenerated struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	if err = json.Unmarshal(body, &regenerated); err != nil || len(regenerated.RecoveryCodes) != auth.RecoveryCodeCount {
		t.Fatalf("invalid regeneration: %s", body)
	}
	if status, _ = scopedAPIRequest(t, server.URL+"/v1/me", recoveryLogin.Token, organizationID, http.MethodGet, nil); status != http.StatusUnauthorized {
		t.Fatalf("MFA change left another session active: status=%d", status)
	}
	concurrentPayload, _ := json.Marshal(map[string]string{"email": userID.String() + "@example.test", "password": password, "recoveryCode": regenerated.RecoveryCodes[0]})
	statuses := make(chan int, 2)
	errorsFound := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response, requestErr := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewReader(concurrentPayload))
			if requestErr != nil {
				errorsFound <- requestErr
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			statuses <- response.StatusCode
		}()
	}
	wait.Wait()
	close(statuses)
	close(errorsFound)
	for requestErr := range errorsFound {
		if requestErr != nil {
			t.Fatal(requestErr)
		}
	}
	successes, rejections := 0, 0
	for status := range statuses {
		if status == http.StatusOK {
			successes++
		}
		if status == http.StatusUnauthorized {
			rejections++
		}
	}
	if successes != 1 || rejections != 1 {
		t.Fatalf("concurrent recovery use successes=%d rejections=%d", successes, rejections)
	}
	status, body = request("/v1/auth/mfa", http.MethodDelete, map[string]string{"currentPassword": password, "recoveryCode": regenerated.RecoveryCodes[1]})
	if status != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", status, body)
	}
	if status, body = login(map[string]string{"email": userID.String() + "@example.test", "password": password}); status != http.StatusOK {
		t.Fatalf("password login after disable status=%d body=%s", status, body)
	}
	var auditCount int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action IN ('auth.mfa.enrollment_started','auth.mfa.enabled','auth.mfa.recovery_codes_regenerated','auth.mfa.disabled')`, organizationID, userID).Scan(&auditCount); err != nil || auditCount != 4 {
		t.Fatalf("MFA audit count=%d err=%v", auditCount, err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action IN ('auth.mfa.enrollment_started','auth.mfa.enabled','auth.mfa.recovery_codes_regenerated','auth.mfa.disabled')`, secondOrganizationID, userID).Scan(&auditCount); err != nil || auditCount != 4 {
		t.Fatalf("cross-tenant MFA audit count=%d err=%v", auditCount, err)
	}
}
