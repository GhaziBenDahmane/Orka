package migrate

import (
	"testing"

	"github.com/google/uuid"
)

func TestCronInterval(t *testing.T) {
	tests := map[string]int{
		"*/15 * * * *": 900,
		"0 * * * *":    3600,
		"15 */6 * * *": 21600,
		"0 2 * * *":    86400,
		"0 2 * * 1":    604800,
		"@daily":       86400,
	}
	for schedule, want := range tests {
		if got, ok := cronInterval(schedule); !ok || got != want {
			t.Errorf("cronInterval(%q) = %d, %v; want %d, true", schedule, got, ok, want)
		}
	}
	for _, schedule := range []string{"*/7 * * * *", "0 0 1 * *", "0 0 * * 1,2", "bad"} {
		if got, ok := cronInterval(schedule); ok {
			t.Errorf("cronInterval(%q) = %d, true; want unsupported", schedule, got)
		}
	}
}

func TestNormalizeS3Endpoint(t *testing.T) {
	if endpoint, tls, err := normalizeS3Endpoint("s3.example.test"); err != nil || endpoint != "https://s3.example.test" || !tls {
		t.Fatalf("endpoint=%q tls=%v err=%v", endpoint, tls, err)
	}
	if endpoint, tls, err := normalizeS3Endpoint("http://minio:9000/"); err != nil || endpoint != "http://minio:9000" || tls {
		t.Fatalf("endpoint=%q tls=%v err=%v", endpoint, tls, err)
	}
	if _, _, err := normalizeS3Endpoint("https://example.test/path"); err == nil {
		t.Fatal("expected endpoint path rejection")
	}
}

func TestDokployVolumePolicyResolvesImportedComposeVolume(t *testing.T) {
	options := DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New()}
	services := []sourceCompose{{id: "compose-1", appName: "legacy-app", compose: "services:\n  web:\n    image: nginx\n    volumes: [uploads:/data]\nvolumes:\n  uploads: {}\n"}}
	serviceID, compose, ok := dokployVolumeService(options, sourceVolumeBackupPolicy{serviceType: "compose", appName: "legacy-app"}, services, nil, map[string]bool{"compose-1": true}, nil)
	if !ok || serviceID != mappedID(options, "compose", "compose-1") {
		t.Fatalf("service=%s ok=%v", serviceID, ok)
	}
	if volume, found := dokployLogicalVolume(compose, "uploads"); !found || volume != "uploads" {
		t.Fatalf("volume=%q found=%v", volume, found)
	}
	if _, found := dokployLogicalVolume(compose, "missing"); found {
		t.Fatal("undeclared volume was accepted")
	}
}
