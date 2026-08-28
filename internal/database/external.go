package database

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/bendahma/dokploy-go/pkg/databaseplugin"
)

type externalDriver struct {
	path        string
	description databaseplugin.Description
}

func (d *externalDriver) Name() string           { return d.description.Name }
func (d *externalDriver) DefaultVersion() string { return d.description.DefaultVersion }
func (d *externalDriver) Render(request Request) (Result, error) {
	response, err := d.call(databaseplugin.Request{Render: &databaseplugin.RenderRequest{Name: request.Name, Version: request.Version, Config: request.Config}}, "render")
	if err != nil || response.Result == nil {
		return Result{}, responseError(err, "driver returned no render result")
	}
	result := response.Result
	if len(result.ComposeYAML) == 0 || len(result.ComposeYAML) > 2<<20 || result.InternalURL == "" {
		return Result{}, errors.New("external driver returned an invalid render result")
	}
	return Result{ComposeYAML: result.ComposeYAML, Environment: result.Environment, Credentials: result.Credentials, InternalURL: result.InternalURL, Version: result.Version}, nil
}

func (d *externalDriver) Backup(version, host string, credentials map[string]string, filename string) (BackupPlan, error) {
	return d.plan("backup", databaseplugin.UtilityRequest{Version: version, Host: host, Credentials: credentials, Filename: filename})
}

func (d *externalDriver) Restore(version, host string, credentials map[string]string, filename string) (RestorePlan, error) {
	return d.plan("restore", databaseplugin.UtilityRequest{Version: version, Host: host, Credentials: credentials, Filename: filename})
}

func (d *externalDriver) Readiness(version, host string, credentials map[string]string) (BackupPlan, error) {
	return d.plan("readiness", databaseplugin.UtilityRequest{Version: version, Host: host, Credentials: credentials})
}

func (d *externalDriver) BackupExtension() (string, bool) {
	for _, capability := range d.description.Capabilities {
		if capability == "backup-restore" && regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`).MatchString(d.description.BackupExtension) {
			return d.description.BackupExtension, true
		}
	}
	return "", false
}

func (d *externalDriver) plan(operation string, request databaseplugin.UtilityRequest) (BackupPlan, error) {
	response, err := d.call(databaseplugin.Request{Utility: &request}, operation)
	if err != nil || response.Plan == nil {
		return BackupPlan{}, responseError(err, "driver returned no utility plan")
	}
	p := response.Plan
	if !registryImagePattern.MatchString(p.Image) || len(p.Command) == 0 || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`).MatchString(p.Extension) {
		return BackupPlan{}, errors.New("external driver returned an unsafe utility plan")
	}
	return BackupPlan{Image: p.Image, Command: p.Command, Environment: p.Environment, Extension: p.Extension, Files: p.Files}, nil
}

func (d *externalDriver) call(request databaseplugin.Request, operation string) (databaseplugin.Response, error) {
	request.ProtocolVersion, request.Operation = databaseplugin.ProtocolVersion, operation
	payload, _ := json.Marshal(request)
	executable, err := openTrustedDriver(d.path)
	if err != nil {
		return databaseplugin.Response{}, fmt.Errorf("open database driver %s: %w", filepath.Base(d.path), err)
	}
	defer executable.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/fd/3")
	command.ExtraFiles = []*os.File{executable}
	// Do not leak the controller's database URL, master key, or provider
	// credentials into an extension process.
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8"}
	command.Stdin = bytes.NewReader(payload)
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = 4<<20, 64<<10
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return databaseplugin.Response{}, fmt.Errorf("database driver %s: %w: %s", d.description.Name, err, stderr.String())
	}
	var response databaseplugin.Response
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return response, err
	}
	if response.ProtocolVersion != databaseplugin.ProtocolVersion {
		return response, errors.New("database driver protocol version mismatch")
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("database driver output exceeds limit")
	}
	return b.Buffer.Write(p)
}

func (r *Registry) LoadExternal(directory string) error {
	if !filepath.IsAbs(directory) {
		return errors.New("database driver directory must be absolute")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("database driver directory must not be a symbolic link")
	}
	if !directoryInfo.IsDir() || directoryInfo.Mode().Perm()&0022 != 0 {
		return errors.New("database driver directory must be a directory and not group/world writable")
	}
	if err := validateDriverOwner(directoryInfo); err != nil {
		return fmt.Errorf("database driver directory: %w", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
			continue
		}
		if info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("database driver %s must not be group/world writable", entry.Name())
		}
		if err := validateDriverOwner(info); err != nil {
			return fmt.Errorf("database driver %s: %w", entry.Name(), err)
		}
		driver := &externalDriver{path: filepath.Join(directory, entry.Name())}
		response, err := driver.call(databaseplugin.Request{}, "describe")
		if err != nil || response.Description == nil {
			return responseError(err, "driver returned no description")
		}
		driver.description = *response.Description
		if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(driver.Name()) || !safeVersion.MatchString(driver.DefaultVersion()) {
			return fmt.Errorf("invalid external database driver description from %s", entry.Name())
		}
		if _, exists := r.drivers[driver.Name()]; exists {
			return fmt.Errorf("database driver %q is already registered", driver.Name())
		}
		r.drivers[driver.Name()] = driver
	}
	return nil
}

func responseError(err error, fallback string) error {
	if err != nil {
		return err
	}
	return errors.New(fallback)
}
