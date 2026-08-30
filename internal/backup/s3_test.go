package backup

import "testing"

func TestS3ConfigurationAndObjectKey(t *testing.T) {
	client, err := NewS3(S3Config{Endpoint: "https://objects.example.test", Bucket: "backups", Prefix: "/tenant/database/", UseTLS: true, AccessKey: "access", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if got := client.ObjectKey("backup.dump"); got != "tenant/database/backup.dump" {
		t.Fatalf("object key = %q", got)
	}
	for _, config := range []S3Config{
		{Endpoint: "ftp://example.test", Bucket: "backups", AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://example.test/path", Bucket: "backups", UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "http://example.test", Bucket: "backups", UseTLS: true, AccessKey: "a", SecretKey: "s"},
		{Endpoint: "http://example.test", Bucket: "", AccessKey: "a", SecretKey: "s"},
	} {
		if _, err = NewS3(config); err == nil {
			t.Fatalf("expected invalid config rejection: %#v", config)
		}
	}
	for _, endpoint := range []string{"https://user@objects.example.test", "https://objects.example.test?token=secret", "https://objects.example.test/#fragment"} {
		if _, err = NewS3(S3Config{Endpoint: endpoint, Bucket: "backups", UseTLS: true, AccessKey: "access", SecretKey: "secret"}); err == nil {
			t.Errorf("unsafe endpoint %q was accepted", endpoint)
		}
	}
}
