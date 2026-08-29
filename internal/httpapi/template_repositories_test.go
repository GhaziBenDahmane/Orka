package httpapi

import "testing"

func TestValidTemplateSyncInterval(t *testing.T) {
	for _, test := range []struct {
		seconds int
		valid   bool
	}{
		{seconds: 0, valid: true},
		{seconds: 299, valid: false},
		{seconds: 300, valid: true},
		{seconds: 3600, valid: true},
		{seconds: 604800, valid: true},
		{seconds: 604801, valid: false},
		{seconds: -1, valid: false},
	} {
		if got := validTemplateSyncInterval(test.seconds); got != test.valid {
			t.Errorf("validTemplateSyncInterval(%d)=%v want %v", test.seconds, got, test.valid)
		}
	}
}
