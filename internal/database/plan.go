package database

import (
	"errors"
	"regexp"
	"strings"
)

const (
	MaxUtilityCommandArguments = 128
	MaxUtilityCommandArgument  = 16 << 10
	MaxUtilityCommandBytes     = 128 << 10
	MaxUtilityEnvironment      = 128
	MaxUtilityEnvironmentValue = 64 << 10
	MaxUtilityEnvironmentBytes = 1 << 20
	MaxUtilityFiles            = 32
	MaxUtilityFileName         = 255
	MaxUtilityFileBytes        = 64 << 10
	MaxUtilityFilesBytes       = 1 << 20
)

var (
	utilityEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	utilityExtension       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
)

// ValidateUtilityPlan validates every driver-controlled value that can reach
// Docker or the agent filesystem. Errors intentionally exclude environment
// values and file contents because both can contain database credentials.
func ValidateUtilityPlan(plan BackupPlan) error {
	if !registryImagePattern.MatchString(plan.Image) || strings.Contains(plan.Image, "..") {
		return errors.New("invalid utility image")
	}
	if len(plan.Command) == 0 || len(plan.Command) > MaxUtilityCommandArguments {
		return errors.New("invalid utility command argument count")
	}
	commandBytes := 0
	for _, argument := range plan.Command {
		if argument == "" || len(argument) > MaxUtilityCommandArgument || strings.ContainsRune(argument, '\x00') {
			return errors.New("invalid utility command argument")
		}
		commandBytes += len(argument)
		if commandBytes > MaxUtilityCommandBytes {
			return errors.New("utility command exceeds size limit")
		}
	}
	if len(plan.Environment) > MaxUtilityEnvironment {
		return errors.New("utility environment exceeds entry limit")
	}
	environmentBytes := 0
	for name, value := range plan.Environment {
		if !utilityEnvironmentName.MatchString(name) {
			return errors.New("invalid utility environment name")
		}
		if len(value) > MaxUtilityEnvironmentValue || strings.ContainsRune(value, '\x00') {
			return errors.New("invalid utility environment value")
		}
		environmentBytes += len(name) + len(value)
		if environmentBytes > MaxUtilityEnvironmentBytes {
			return errors.New("utility environment exceeds size limit")
		}
	}
	if plan.Extension != "" && !utilityExtension.MatchString(plan.Extension) {
		return errors.New("invalid utility artifact extension")
	}
	return ValidateUtilityFiles(plan.Files)
}

// ValidateUtilityFiles is also used immediately before filesystem writes so a
// future plan producer cannot accidentally bypass the primary validator.
func ValidateUtilityFiles(files map[string]string) error {
	if len(files) > MaxUtilityFiles {
		return errors.New("utility files exceed entry limit")
	}
	total := 0
	for name, content := range files {
		if err := ValidateUtilityFileName(name); err != nil {
			return errors.New("invalid utility file name")
		}
		if len(content) > MaxUtilityFileBytes {
			return errors.New("utility file exceeds size limit")
		}
		total += len(content)
		if total > MaxUtilityFilesBytes {
			return errors.New("utility files exceed size limit")
		}
	}
	return nil
}

// ValidateUtilityFileName applies portable basename rules. In particular,
// backslashes are rejected even when the controller or agent runs on Linux.
func ValidateUtilityFileName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > MaxUtilityFileName || strings.ContainsAny(name, "/\\\x00") {
		return errors.New("invalid utility file name")
	}
	return nil
}
