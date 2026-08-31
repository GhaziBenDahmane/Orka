package store

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNormalizeServiceScheduleRejectsUnsafeMetadata(t *testing.T) {
	valid := ServiceSchedule{Name: "Database cleanup", Description: "Runs a safe cleanup\ninside the application container.", CronExpression: "0 * * * *", Timezone: "UTC", TargetService: "api", Shell: "sh", Command: "printf 'ok\\n'", TimeoutSeconds: 30}
	if _, err := normalizeServiceSchedule(valid, time.Now()); err != nil {
		t.Fatalf("valid schedule rejected: %v", err)
	}

	tests := []ServiceSchedule{
		withScheduleName(valid, "line\nbreak"),
		withScheduleName(valid, "hidden\u0085break"),
		withScheduleName(valid, string([]byte{'x', 0xff})),
		withScheduleName(valid, strings.Repeat("n", 121)),
		withScheduleDescription(valid, "unsafe\x00description"),
		withScheduleDescription(valid, string([]byte{'x', 0xff})),
	}
	for index, input := range tests {
		if _, err := normalizeServiceSchedule(input, time.Now()); !errors.Is(err, ErrInvalidSchedule) {
			t.Errorf("invalid schedule %d returned %v", index, err)
		}
	}
}

func withScheduleName(input ServiceSchedule, name string) ServiceSchedule {
	input.Name = name
	return input
}

func withScheduleDescription(input ServiceSchedule, description string) ServiceSchedule {
	input.Description = description
	return input
}
