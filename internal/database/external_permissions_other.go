//go:build !linux

package database

import (
	"errors"
	"os"
	"os/exec"
)

func validateDriverOwner(os.FileInfo) error {
	return errors.New("external database drivers are only supported on Linux")
}

func openTrustedDriver(string) (*os.File, error) {
	return nil, errors.New("external database drivers are only supported on Linux")
}

func configureExternalDriverCommand(*exec.Cmd) {}

func terminateExternalDriverProcessGroup(*exec.Cmd) error { return nil }
