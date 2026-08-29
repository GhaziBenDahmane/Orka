package database

import (
	"strings"
	"testing"
)

func TestValidateUtilityPlanRejectsUnsafeValuesWithoutLeakingContents(t *testing.T) {
	valid := BackupPlan{Image: "registry.example/db-tools:1", Command: []string{"db-dump", "--output=/backup/data.dump"}, Environment: map[string]string{"DB_PASSWORD": "secret"}, Extension: "dump", Files: map[string]string{"client.conf": "password=file-secret"}}
	if err := ValidateUtilityPlan(valid); err != nil {
		t.Fatal(err)
	}

	tests := map[string]BackupPlan{
		"image traversal":   {Image: "example/../tools:1", Command: []string{"dump"}},
		"empty argument":    {Image: "tools:1", Command: []string{"dump", ""}},
		"nul argument":      {Image: "tools:1", Command: []string{"dump", "argument-secret\x00suffix"}},
		"large argument":    {Image: "tools:1", Command: []string{"dump", strings.Repeat("a", MaxUtilityCommandArgument+1)}},
		"many arguments":    {Image: "tools:1", Command: append([]string{"dump"}, repeatedStrings(MaxUtilityCommandArguments, "x")...)},
		"environment name":  {Image: "tools:1", Command: []string{"dump"}, Environment: map[string]string{"BAD-NAME": "environment-secret"}},
		"environment nul":   {Image: "tools:1", Command: []string{"dump"}, Environment: map[string]string{"PASSWORD": "environment-secret\x00suffix"}},
		"environment value": {Image: "tools:1", Command: []string{"dump"}, Environment: map[string]string{"PASSWORD": strings.Repeat("s", MaxUtilityEnvironmentValue+1)}},
		"relative file":     {Image: "tools:1", Command: []string{"dump"}, Files: map[string]string{"../escape": "file-secret"}},
		"absolute file":     {Image: "tools:1", Command: []string{"dump"}, Files: map[string]string{"/escape": "file-secret"}},
		"slash file":        {Image: "tools:1", Command: []string{"dump"}, Files: map[string]string{"dir/file": "file-secret"}},
		"backslash file":    {Image: "tools:1", Command: []string{"dump"}, Files: map[string]string{`dir\file`: "file-secret"}},
		"dot file":          {Image: "tools:1", Command: []string{"dump"}, Files: map[string]string{".": "file-secret"}},
		"large file":        {Image: "tools:1", Command: []string{"dump"}, Files: map[string]string{"config": strings.Repeat("s", MaxUtilityFileBytes+1)}},
		"invalid extension": {Image: "tools:1", Command: []string{"dump"}, Extension: "../dump"},
	}
	for name, plan := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateUtilityPlan(plan)
			if err == nil {
				t.Fatal("expected unsafe plan to be rejected")
			}
			for _, secret := range []string{"argument-secret", "environment-secret", "file-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("validation error leaked controlled content: %v", err)
				}
			}
		})
	}
}

func TestValidateUtilityPlanRejectsAggregateLimits(t *testing.T) {
	command := append([]string{"dump"}, repeatedStrings(9, strings.Repeat("x", MaxUtilityCommandArgument))...)
	if err := ValidateUtilityPlan(BackupPlan{Image: "tools:1", Command: command}); err == nil {
		t.Fatal("expected aggregate command size rejection")
	}
	environment := make(map[string]string, MaxUtilityEnvironment+1)
	for index := 0; index <= MaxUtilityEnvironment; index++ {
		environment["VALUE_"+strings.Repeat("X", index/10)+string(rune('A'+index%10))] = "x"
	}
	if err := ValidateUtilityPlan(BackupPlan{Image: "tools:1", Command: []string{"dump"}, Environment: environment}); err == nil {
		t.Fatal("expected environment entry limit rejection")
	}
	environment = make(map[string]string, 17)
	for index := 0; index < 17; index++ {
		environment["VALUE_"+string(rune('A'+index))] = strings.Repeat("x", MaxUtilityEnvironmentValue)
	}
	if err := ValidateUtilityPlan(BackupPlan{Image: "tools:1", Command: []string{"dump"}, Environment: environment}); err == nil {
		t.Fatal("expected aggregate environment size rejection")
	}
	files := make(map[string]string, MaxUtilityFiles+1)
	for index := 0; index <= MaxUtilityFiles; index++ {
		files["file-"+string(rune('A'+index))] = "x"
	}
	if err := ValidateUtilityPlan(BackupPlan{Image: "tools:1", Command: []string{"dump"}, Files: files}); err == nil {
		t.Fatal("expected file entry limit rejection")
	}
	files = make(map[string]string, 17)
	for index := 0; index < 17; index++ {
		files["file-"+string(rune('A'+index))] = strings.Repeat("x", MaxUtilityFileBytes)
	}
	if err := ValidateUtilityPlan(BackupPlan{Image: "tools:1", Command: []string{"dump"}, Files: files}); err == nil {
		t.Fatal("expected aggregate file size rejection")
	}
}

func repeatedStrings(count int, value string) []string {
	values := make([]string, count)
	for index := range values {
		values[index] = value
	}
	return values
}
