package ociref

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/bendahma/dokploy-go/internal/netpolicy"
)

const maxRepositoryBytes = 255

var (
	pathComponentPattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	tagPattern           = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	digestPattern        = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type Reference struct {
	Repository string
	Registry   string
	Tag        string
	Digest     string
}

func Parse(raw string) (Reference, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\x00\r\n") || strings.Count(raw, "@") > 1 {
		return Reference{}, errors.New("invalid OCI image reference")
	}
	nameAndTag, digest, hasDigest := strings.Cut(raw, "@")
	if hasDigest && !digestPattern.MatchString(digest) {
		return Reference{}, errors.New("invalid OCI image digest")
	}
	repository, tag := nameAndTag, ""
	if colon := strings.LastIndexByte(nameAndTag, ':'); colon > strings.LastIndexByte(nameAndTag, '/') {
		repository, tag = nameAndTag[:colon], nameAndTag[colon+1:]
		if !tagPattern.MatchString(tag) {
			return Reference{}, errors.New("invalid OCI image tag")
		}
	}
	registry, err := validateRepository(repository)
	if err != nil {
		return Reference{}, err
	}
	return Reference{Repository: repository, Registry: registry, Tag: tag, Digest: digest}, nil
}

func ParseRepository(raw string) (Reference, error) {
	reference, err := Parse(raw)
	if err != nil || reference.Tag != "" || reference.Digest != "" {
		return Reference{}, errors.New("OCI repository must not include a tag or digest")
	}
	return reference, nil
}

func IsDigestPinned(raw string) bool {
	reference, err := Parse(raw)
	return err == nil && reference.Digest != ""
}

func validateRepository(repository string) (string, error) {
	if repository == "" || len(repository) > maxRepositoryBytes {
		return "", errors.New("invalid OCI image repository")
	}
	registry, path := splitRegistry(repository)
	if path == "" {
		return "", errors.New("invalid OCI image repository")
	}
	endpoint, err := url.Parse("https://" + registry)
	if err != nil || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" || !netpolicy.ValidURLHost(endpoint) {
		return "", errors.New("invalid OCI registry authority")
	}
	for _, component := range strings.Split(path, "/") {
		if len(component) > 255 || !pathComponentPattern.MatchString(component) {
			return "", errors.New("invalid OCI repository path")
		}
	}
	return strings.ToLower(registry), nil
}

func splitRegistry(repository string) (string, string) {
	first, rest, hasSlash := strings.Cut(repository, "/")
	if hasSlash && (strings.ContainsAny(first, ".:") || strings.EqualFold(first, "localhost") || strings.HasPrefix(first, "[")) {
		return first, rest
	}
	return "docker.io", repository
}
