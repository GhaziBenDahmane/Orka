package schedule

import (
	"testing"
	"time"
)

func TestNextHonorsTimezone(t *testing.T) {
	after := time.Date(2026, time.March, 1, 7, 30, 0, 0, time.UTC)
	next, err := Next("0 9 * * *", "Europe/Paris", after)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, time.March, 1, 8, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("next=%s want=%s", next, want)
	}
}

func TestNextRejectsSecondsAndUnknownTimezone(t *testing.T) {
	if _, err := Next("0 0 9 * * *", "UTC", time.Now()); err == nil {
		t.Fatal("expected six-field expression rejection")
	}
	if _, err := Next("0 9 * * *", "Mars/Olympus", time.Now()); err == nil {
		t.Fatal("expected timezone rejection")
	}
}
