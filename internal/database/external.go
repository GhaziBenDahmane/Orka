package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bendahma/dokploy-go/pkg/databaseplugin"
)

type externalDriver struct {
	path        string
	digest      string
	description databaseplugin.Description
}

const maxExternalDriverBytes = 64 << 20
const externalDriverWaitDelay = time.Second

const (
	maxExternalRenderEntries    = 128
	maxExternalRenderValueBytes = 64 << 10
	maxExternalRenderMapBytes   = 1 << 20
	maxExternalInternalURLBytes = 16 << 10
)

var (
	externalCredentialName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)
	externalDatabaseHost   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	externalDatabaseName   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	externalArtifactName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
	externalURLScheme      = regexp.MustCompile(`^[a-z][a-z0-9+.-]{0,31}$`)
)

func (d *externalDriver) Name() string           { return d.description.Name }
func (d *externalDriver) DefaultVersion() string { return d.description.DefaultVersion }
func (d *externalDriver) Render(request Request) (Result, error) {
	if !externalDatabaseName.MatchString(request.Name) || !safeVersion.MatchString(request.Version) {
		return Result{}, errors.New("invalid external database render parameters")
	}
	response, err := d.call(databaseplugin.Request{Render: &databaseplugin.RenderRequest{Name: request.Name, Version: request.Version, Config: request.Config}}, "render")
	if err != nil || response.Result == nil {
		return Result{}, responseError(err, "driver returned no render result")
	}
	result := response.Result
	if len(result.ComposeYAML) == 0 || len(result.ComposeYAML) > 2<<20 || !safeVersion.MatchString(result.Version) {
		return Result{}, errors.New("external driver returned an invalid render result")
	}
	if err := validateExternalStringMap(result.Environment, utilityEnvironmentName); err != nil {
		return Result{}, errors.New("external driver returned an invalid render environment")
	}
	if err := validateExternalStringMap(result.Credentials, externalCredentialName); err != nil {
		return Result{}, errors.New("external driver returned invalid credentials")
	}
	if err := validateExternalInternalURL(result.InternalURL); err != nil {
		return Result{}, errors.New("external driver returned an invalid internal URL")
	}
	return Result{ComposeYAML: result.ComposeYAML, Environment: result.Environment, Credentials: result.Credentials, InternalURL: result.InternalURL, Version: result.Version}, nil
}

func validateExternalStringMap(values map[string]string, namePattern *regexp.Regexp) error {
	if len(values) > maxExternalRenderEntries {
		return errors.New("entry limit exceeded")
	}
	total := 0
	for name, value := range values {
		if !namePattern.MatchString(name) || len(value) > maxExternalRenderValueBytes || strings.ContainsRune(value, '\x00') {
			return errors.New("invalid entry")
		}
		total += len(name) + len(value)
		if total > maxExternalRenderMapBytes {
			return errors.New("size limit exceeded")
		}
	}
	return nil
}

func validateExternalInternalURL(raw string) error {
	if raw == "" || len(raw) > maxExternalInternalURLBytes || !utf8.ValidString(raw) || strings.IndexFunc(raw, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}) >= 0 {
		return errors.New("invalid URL bytes")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || !externalURLScheme.MatchString(parsed.Scheme) || parsed.Host == "" || parsed.Hostname() == "" || parsed.Fragment != "" {
		return errors.New("invalid absolute URL")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return errors.New("invalid URL port")
		}
	}
	return nil
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
	if (operation == "backup" || operation == "restore") && !d.hasCapability("backup-restore") {
		return BackupPlan{}, errors.New("external database driver does not declare backup and restore support")
	}
	if err := d.validateUtilityRequest(operation, request); err != nil {
		return BackupPlan{}, err
	}
	response, err := d.call(databaseplugin.Request{Utility: &request}, operation)
	if err != nil || response.Plan == nil {
		return BackupPlan{}, responseError(err, "driver returned no utility plan")
	}
	p := response.Plan
	plan := BackupPlan{Image: p.Image, Command: p.Command, Environment: p.Environment, Extension: p.Extension, Files: p.Files}
	if err := ValidateUtilityPlan(plan); err != nil {
		return BackupPlan{}, errors.New("external driver returned an unsafe utility plan")
	}
	if (operation == "backup" || operation == "restore") && plan.Extension != d.description.BackupExtension {
		return BackupPlan{}, errors.New("external driver returned an inconsistent artifact extension")
	}
	return plan, nil
}

func (d *externalDriver) validateUtilityRequest(operation string, request databaseplugin.UtilityRequest) error {
	if !safeVersion.MatchString(request.Version) || !externalDatabaseHost.MatchString(request.Host) {
		return errors.New("invalid external database utility parameters")
	}
	if err := validateExternalStringMap(request.Credentials, externalCredentialName); err != nil {
		return errors.New("invalid external database utility credentials")
	}
	switch operation {
	case "readiness":
		if request.Filename != "" {
			return errors.New("invalid external database readiness filename")
		}
	case "backup", "restore":
		extension, supported := d.BackupExtension()
		if !supported || !externalArtifactName.MatchString(request.Filename) || !strings.HasSuffix(request.Filename, "."+extension) {
			return errors.New("invalid external database utility filename")
		}
	default:
		return errors.New("invalid external database utility operation")
	}
	return nil
}

func (d *externalDriver) hasCapability(expected string) bool {
	for _, capability := range d.description.Capabilities {
		if capability == expected {
			return true
		}
	}
	return false
}

func (d *externalDriver) call(request databaseplugin.Request, operation string) (databaseplugin.Response, error) {
	request.ProtocolVersion, request.Operation = databaseplugin.ProtocolVersion, operation
	payload, err := json.Marshal(request)
	if err != nil {
		return databaseplugin.Response{}, errors.New("encode database driver request")
	}
	if len(payload) > databaseplugin.MaxRequestBytes {
		return databaseplugin.Response{}, errors.New("database driver request exceeds size limit")
	}
	executable, err := openTrustedDriver(d.path)
	if err != nil {
		return databaseplugin.Response{}, fmt.Errorf("open database driver %s: %w", filepath.Base(d.path), err)
	}
	defer executable.Close()
	digest, err := externalDriverDigest(executable)
	if err != nil {
		return databaseplugin.Response{}, fmt.Errorf("verify database driver %s: %w", filepath.Base(d.path), err)
	}
	if d.digest == "" {
		d.digest = digest
	} else if d.digest != digest {
		return databaseplugin.Response{}, fmt.Errorf("database driver %s changed since startup", driverLabel(d))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/fd/3")
	command.ExtraFiles = []*os.File{executable}
	configureExternalDriverCommand(command)
	// A faulty driver may fork a child that inherits stdout or stderr. Bound
	// the post-exit pipe drain so that such a child cannot hold a controller
	// worker indefinitely after the driver exits or its context is cancelled.
	command.WaitDelay = externalDriverWaitDelay
	// Do not leak the controller's database URL, master key, or provider
	// credentials into an extension process. Use a fixed system path rather
	// than inheriting a potentially attacker-controlled controller PATH.
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	command.Stdin = bytes.NewReader(payload)
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = 4<<20, 64<<10
	command.Stdout, command.Stderr = &stdout, &stderr
	runErr := command.Run()
	cleanupErr := terminateExternalDriverProcessGroup(command)
	if runErr != nil || cleanupErr != nil {
		// Requests can contain plaintext credentials and render inputs. Never
		// propagate extension-controlled stderr into API, job, or audit errors.
		return databaseplugin.Response{}, fmt.Errorf("database driver %s failed during %s: %w", driverLabel(d), operation, errors.Join(runErr, cleanupErr))
	}
	var response databaseplugin.Response
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return response, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return response, errors.New("database driver returned trailing protocol data")
	}
	if response.ProtocolVersion != databaseplugin.ProtocolVersion {
		return response, errors.New("database driver protocol version mismatch")
	}
	if response.Error != "" {
		if response.Description != nil || response.Result != nil || response.Plan != nil {
			return response, errors.New("database driver returned an invalid error response shape")
		}
		return response, fmt.Errorf("database driver %s reported a failure during %s", driverLabel(d), operation)
	}
	if !validExternalResponseShape(response, operation) {
		return response, errors.New("database driver returned an invalid response shape")
	}
	return response, nil
}

func validExternalResponseShape(response databaseplugin.Response, operation string) bool {
	switch operation {
	case "describe":
		return response.Description != nil && response.Result == nil && response.Plan == nil
	case "render":
		return response.Description == nil && response.Result != nil && response.Plan == nil
	case "backup", "restore", "readiness":
		return response.Description == nil && response.Result == nil && response.Plan != nil
	default:
		return false
	}
}

func externalDriverDigest(executable *os.File) (string, error) {
	info, err := executable.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() < 1 || info.Size() > maxExternalDriverBytes {
		return "", errors.New("executable size is outside the allowed range")
	}
	if _, err = executable.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, executable); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func driverLabel(driver *externalDriver) string {
	if driver.description.Name != "" {
		return driver.description.Name
	}
	return filepath.Base(driver.path)
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
	pending := make(map[string]*externalDriver)
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
		if !validExternalDescription(driver.description) {
			return fmt.Errorf("invalid external database driver description from %s", entry.Name())
		}
		if _, exists := r.drivers[driver.Name()]; exists {
			return fmt.Errorf("database driver %q is already registered", driver.Name())
		}
		if _, exists := pending[driver.Name()]; exists {
			return fmt.Errorf("database driver %q is already registered", driver.Name())
		}
		pending[driver.Name()] = driver
	}
	if len(pending) == 0 {
		return errors.New("database driver directory contains no trusted executable drivers")
	}
	for name, driver := range pending {
		r.drivers[name] = driver
	}
	return nil
}

func validExternalDescription(description databaseplugin.Description) bool {
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(description.Name) || !safeVersion.MatchString(description.DefaultVersion) {
		return false
	}
	seen := make(map[string]struct{}, len(description.Capabilities))
	for _, capability := range description.Capabilities {
		if capability != "backup-restore" {
			return false
		}
		if _, exists := seen[capability]; exists {
			return false
		}
		seen[capability] = struct{}{}
	}
	_, backupRestore := seen["backup-restore"]
	return backupRestore == utilityExtension.MatchString(description.BackupExtension) && (backupRestore || description.BackupExtension == "")
}

func responseError(err error, fallback string) error {
	if err != nil {
		return err
	}
	return errors.New(fallback)
}
