package templates

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bendahma/dokploy-go/internal/store"
)

const maxCatalogArchiveBytes int64 = 64 << 20
const maxCatalogFileBytes int64 = 4 << 20
const maxCatalogFiles = 10000

var githubPart = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func GitHubArchiveURL(repositoryURL, gitRef string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(repositoryURL))
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "github.com") || u.Port() != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("repositoryUrl must be an https://github.com/owner/repository URL")
	}
	parts := strings.Split(strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/"), "/")
	if len(parts) != 2 || !githubPart.MatchString(parts[0]) || !githubPart.MatchString(parts[1]) {
		return "", errors.New("repositoryUrl must identify one GitHub owner and repository")
	}
	gitRef = strings.TrimSpace(gitRef)
	if gitRef == "" || len(gitRef) > 200 || strings.ContainsAny(gitRef, "\\\x00") || strings.Contains(gitRef, "..") {
		return "", errors.New("gitRef is invalid")
	}
	return "https://codeload.github.com/" + parts[0] + "/" + parts[1] + "/tar.gz/" + url.PathEscape(gitRef), nil
}

func FetchGitHubCatalog(ctx context.Context, client *http.Client, repositoryURL, gitRef string) (string, func(), error) {
	archiveURL, err := GitHubArchiveURL(repositoryURL, gitRef)
	if err != nil {
		return "", nil, err
	}
	if client == nil {
		client = &http.Client{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("download template repository: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("download template repository returned HTTP %d", resp.StatusCode)
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
	tarReader, files, extracted := tar.NewReader(gz), 0, int64(0)
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
		clean := filepath.Clean(filepath.FromSlash(header.Name))
		parts := strings.Split(clean, string(filepath.Separator))
		if len(parts) < 2 {
			continue
		}
		relative := filepath.Join(parts[1:]...)
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
			files++
			extracted += header.Size
			if files > maxCatalogFiles || header.Size < 0 || header.Size > maxCatalogFileBytes || extracted > maxCatalogArchiveBytes {
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
	return directory, cleanup, nil
}

// VerifyRepositoryCatalog applies the repository's trust policy before any
// catalog entries are imported. Supplying a key always enables verification;
// requireSignature additionally prevents an accidentally unconfigured key.
func VerifyRepositoryCatalog(repository store.TemplateRepository, root string) (string, error) {
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
	catalogRoot := filepath.Join(root, filepath.FromSlash(repository.CatalogPath))
	if err = VerifyCatalog(catalogRoot, key); err != nil {
		return "", fmt.Errorf("verify signed template repository: %w", err)
	}
	return PublicKeyFingerprint(key), nil
}
