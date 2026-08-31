package templates

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
)

const maxCatalogArchiveBytes int64 = 64 << 20
const maxCatalogExpandedBytes int64 = 128 << 20
const maxCatalogFileBytes int64 = 4 << 20
const maxCatalogEntries = 10000
const maxCatalogPathBytes = 1024
const maxCatalogPathDepth = 32
const maxGitHubRepositoryURLBytes = 2048
const maxGitHubOwnerBytes = 39
const maxGitHubRepositoryBytes = 100
const maxGitHubTokenBytes = 16 << 10

var githubPart = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func GitHubArchiveURL(repositoryURL, gitRef string) (string, error) {
	repositoryURL = strings.TrimSpace(repositoryURL)
	if len(repositoryURL) > maxGitHubRepositoryURLBytes {
		return "", errors.New("repositoryUrl is too long")
	}
	u, err := url.Parse(repositoryURL)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "github.com") || u.Port() != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("repositoryUrl must be an https://github.com/owner/repository URL")
	}
	parts := strings.Split(strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/"), "/")
	if len(parts) != 2 || len(parts[0]) > maxGitHubOwnerBytes || len(parts[1]) > maxGitHubRepositoryBytes || parts[0] == "." || parts[0] == ".." || parts[1] == "." || parts[1] == ".." || !githubPart.MatchString(parts[0]) || !githubPart.MatchString(parts[1]) {
		return "", errors.New("repositoryUrl must identify one GitHub owner and repository")
	}
	gitRef = strings.TrimSpace(gitRef)
	if !validGitHubRef(gitRef) {
		return "", errors.New("gitRef is invalid")
	}
	return "https://codeload.github.com/" + parts[0] + "/" + parts[1] + "/tar.gz/" + url.PathEscape(gitRef), nil
}

func NormalizeCatalogPath(raw string) (string, error) {
	candidate := strings.Trim(strings.TrimSpace(raw), "/")
	if candidate == "" {
		return "", nil
	}
	clean := path.Clean(candidate)
	parts := strings.Split(clean, "/")
	if clean != candidate || len(clean) > maxCatalogPathBytes || len(parts) > maxCatalogPathDepth || path.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.ContainsRune(raw, '\\') || unsafeCatalogText(raw) {
		return "", errors.New("catalogPath must be a canonical relative path")
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 255 {
			return "", errors.New("catalogPath contains an invalid segment")
		}
	}
	return clean, nil
}

func FetchGitHubCatalog(ctx context.Context, client *http.Client, repositoryURL, gitRef, token string) (string, func(), error) {
	archiveURL, err := GitHubArchiveURL(repositoryURL, gitRef)
	if err != nil {
		return "", nil, err
	}
	return fetchCatalogArchive(ctx, client, archiveURL, token)
}

func fetchCatalogArchive(ctx context.Context, client *http.Client, archiveURL, token string) (string, func(), error) {
	if len(token) > maxGitHubTokenBytes || strings.ContainsAny(token, "\x00\r\n") {
		return "", nil, errors.New("template repository token is invalid")
	}
	client = catalogHTTPClient(client)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, nil)
	if err != nil {
		return "", nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("download template repository: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("download template repository returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxCatalogArchiveBytes {
		return "", nil, errors.New("template repository archive exceeds 64 MiB")
	}
	limited := &io.LimitedReader{R: resp.Body, N: maxCatalogArchiveBytes + 1}
	gz, err := gzip.NewReader(limited)
	if err != nil {
		return "", nil, errors.New("template repository is not a gzip archive")
	}
	defer gz.Close()
	directory, err := os.MkdirTemp("", "dockyard-catalog-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	expanded := &io.LimitedReader{R: gz, N: maxCatalogExpandedBytes + 1}
	tarReader, entries, extracted := tar.NewReader(expanded), 0, int64(0)
	archiveRoot := ""
	for {
		header, readErr := tarReader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			cleanup()
			return "", nil, fmt.Errorf("read template repository: %w", readErr)
		}
		if limited.N <= 0 {
			cleanup()
			return "", nil, errors.New("template repository archive exceeds 64 MiB")
		}
		entries++
		if entries > maxCatalogEntries {
			cleanup()
			return "", nil, errors.New("template repository exceeds entry limit")
		}
		_, parts, pathErr := canonicalCatalogArchivePath(header.Name, header.Typeflag == tar.TypeDir)
		if pathErr != nil {
			cleanup()
			return "", nil, pathErr
		}
		if archiveRoot == "" {
			if parts[0] == "." || parts[0] == ".." || !githubPart.MatchString(parts[0]) {
				cleanup()
				return "", nil, errors.New("template repository has an invalid archive root")
			}
			archiveRoot = parts[0]
		} else if parts[0] != archiveRoot {
			cleanup()
			return "", nil, errors.New("template repository contains multiple archive roots")
		}
		if len(parts) < 2 {
			continue
		}
		relative := filepath.FromSlash(strings.Join(parts[1:], "/"))
		if relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			cleanup()
			return "", nil, errors.New("template repository contains an unsafe path")
		}
		target := filepath.Join(directory, relative)
		switch header.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(target, 0750); err != nil {
				cleanup()
				return "", nil, err
			}
		case tar.TypeReg:
			extracted += header.Size
			if header.Size < 0 || header.Size > maxCatalogFileBytes || extracted > maxCatalogArchiveBytes {
				cleanup()
				return "", nil, errors.New("template repository exceeds extraction limits")
			}
			if err = os.MkdirAll(filepath.Dir(target), 0750); err != nil {
				cleanup()
				return "", nil, err
			}
			file, createErr := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
			if createErr != nil {
				cleanup()
				return "", nil, createErr
			}
			_, copyErr := io.CopyN(file, tarReader, header.Size)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil {
				cleanup()
				return "", nil, errors.New("extract template repository")
			}
		default:
			cleanup()
			return "", nil, errors.New("template repository links and special files are not allowed")
		}
	}
	if _, err = io.Copy(io.Discard, expanded); err != nil {
		cleanup()
		return "", nil, errors.New("read template repository gzip stream")
	}
	if expanded.N <= 0 {
		cleanup()
		return "", nil, errors.New("template repository expanded archive exceeds 128 MiB")
	}
	if limited.N <= 0 {
		cleanup()
		return "", nil, errors.New("template repository archive exceeds 64 MiB")
	}
	if archiveRoot == "" {
		cleanup()
		return "", nil, errors.New("template repository archive is empty")
	}
	return directory, cleanup, nil
}

func canonicalCatalogArchivePath(name string, directory bool) (string, []string, error) {
	if name == "" || len(name) > maxCatalogPathBytes || strings.ContainsRune(name, '\\') || unsafeCatalogText(name) {
		return "", nil, errors.New("template repository contains an unsafe path")
	}
	candidate := name
	if directory && strings.HasSuffix(candidate, "/") {
		candidate = strings.TrimSuffix(candidate, "/")
	}
	clean := path.Clean(candidate)
	if candidate == "" || clean != candidate || path.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", nil, errors.New("template repository contains a non-canonical path")
	}
	parts := strings.Split(clean, "/")
	if len(parts) > maxCatalogPathDepth+1 {
		return "", nil, errors.New("template repository path exceeds depth limit")
	}
	for _, part := range parts {
		if part == "" || len(part) > 255 {
			return "", nil, errors.New("template repository contains an invalid path segment")
		}
	}
	return clean, parts, nil
}

func catalogHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
	}
	secured := *client
	if secured.Transport == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		secured.Transport = transport
	}
	secured.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("template repository redirects are disabled")
	}
	return &secured
}

func validGitHubRef(ref string) bool {
	if ref == "" || len(ref) > 200 || ref == "@" || strings.HasPrefix(ref, ".") || strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, ".") || strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".lock") || strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.Contains(ref, "//") {
		return false
	}
	return !strings.ContainsAny(ref, " ~^:?*[\\") && !unsafeCatalogText(ref)
}

func unsafeCatalogText(value string) bool {
	return !utf8.ValidString(value) || strings.IndexFunc(value, func(char rune) bool {
		return unicode.IsControl(char) || unicode.In(char, unicode.Cf, unicode.Zl, unicode.Zp)
	}) >= 0
}

// VerifyRepositoryCatalog applies the repository's trust policy before any
// catalog entries are imported. Supplying a key always enables verification;
// requireSignature additionally prevents an accidentally unconfigured key.
func VerifyRepositoryCatalog(repository store.TemplateRepository, root string) (string, error) {
	catalogPath, err := NormalizeCatalogPath(repository.CatalogPath)
	if err != nil {
		return "", err
	}
	raw := strings.TrimSpace(repository.TrustedPublicKey)
	if raw == "" {
		if repository.RequireSignature {
			return "", errors.New("template repository requires a trusted catalog public key")
		}
		return "", nil
	}
	key, err := ParsePublicKey([]byte(raw))
	if err != nil {
		return "", fmt.Errorf("parse trusted catalog public key: %w", err)
	}
	catalogRoot := filepath.Join(root, filepath.FromSlash(catalogPath))
	if err = VerifyCatalog(catalogRoot, key); err != nil {
		return "", fmt.Errorf("verify signed template repository: %w", err)
	}
	return PublicKeyFingerprint(key), nil
}

func SyncClaimedRepository(ctx context.Context, db *store.Store, box *cryptox.Box, client *http.Client, repository store.TemplateRepository) (ImportReport, error) {
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
	}
	token, err := repositoryToken(ctx, db, box, repository)
	if err != nil {
		metadata := map[string]any{"imported": 0, "restricted": 0, "invalid": 0, "failed": 0, "scheduled": true, "error": boundedSyncError(err)}
		return ImportReport{}, errors.Join(err, db.FinishTemplateRepositorySyncWithAudit(ctx, repository, "failed", boundedSyncError(err), "scheduler", metadata))
	}
	root, cleanup, err := FetchGitHubCatalog(ctx, client, repository.RepositoryURL, repository.GitRef, token)
	if err == nil {
		defer cleanup()
		_, err = VerifyRepositoryCatalog(repository, root)
	}
	var report ImportReport
	var items []store.Template
	if err == nil {
		report, items, err = ParseRepositoryCatalog(repository, root)
	}
	metadata := map[string]any{"imported": report.Imported, "restricted": report.Restricted, "invalid": report.Invalid, "failed": len(report.Failed), "scheduled": true}
	if err != nil {
		metadata["error"] = boundedSyncError(err)
		if finishErr := db.FinishTemplateRepositorySyncWithAudit(ctx, repository, "failed", boundedSyncError(err), "scheduler", metadata); finishErr != nil {
			err = errors.Join(err, finishErr)
		}
		return report, err
	}
	if err = db.PublishRepositoryTemplatesForSyncWithAudit(ctx, repository, items, "scheduler", metadata); err != nil {
		return report, err
	}
	return report, nil
}

func repositoryToken(ctx context.Context, db *store.Store, box *cryptox.Box, repository store.TemplateRepository) (string, error) {
	if repository.CredentialID == nil {
		return "", nil
	}
	if box == nil {
		return "", errors.New("template repository credential decryption is unavailable")
	}
	credential, err := db.GetSourceCredential(ctx, repository.OrganizationID, *repository.CredentialID)
	if err != nil {
		return "", fmt.Errorf("load template repository credential: %w", err)
	}
	if credential.Kind != "git" || !strings.EqualFold(strings.TrimSpace(credential.Server), "github.com") {
		return "", errors.New("template repository credential is not a GitHub HTTPS token")
	}
	plain, err := box.DecryptResource(credential.EncryptedSecret, "source-credential", credential.ID.String(), "source-credential")
	if err != nil {
		return "", fmt.Errorf("decrypt template repository credential: %w", err)
	}
	if token := strings.TrimSpace(string(plain)); token != "" && len(token) <= maxGitHubTokenBytes && !strings.ContainsAny(token, "\x00\r\n") {
		return token, nil
	}
	return "", errors.New("template repository credential is empty")
}

func boundedSyncError(err error) string {
	message := strings.ToValidUTF8(err.Error(), "�")
	if len(message) > 1000 {
		message = message[:1000]
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
	}
	return message
}

func RunRepositorySyncScheduler(ctx context.Context, db *store.Store, box *cryptox.Box, client *http.Client, logger *slog.Logger, holder string) {
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
	}
	if logger == nil {
		logger = slog.Default()
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		leader, err := db.AcquireControllerLease(ctx, "template-repository-scheduler", holder, 90*time.Second)
		if err != nil && ctx.Err() == nil {
			logger.Error("acquire template repository scheduler lease", "error", err)
		} else if leader {
			for ctx.Err() == nil {
				repository, claimErr := db.ClaimDueTemplateRepository(ctx)
				if errors.Is(claimErr, store.ErrNotFound) {
					break
				}
				if claimErr != nil {
					logger.Error("claim due template repository", "error", claimErr)
					break
				}
				_, syncErr := SyncClaimedRepository(ctx, db, box, client, repository)
				if syncErr != nil {
					logger.Error("scheduled template repository sync", "repository_id", repository.ID, "error", syncErr)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
