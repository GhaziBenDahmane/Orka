package volumeartifact

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxArchiveEntries = 1_000_000
	maxArchivePath    = 4096
	internalPrefix    = ".dockyard-restore-"
)

type archiveEntry struct {
	header *tar.Header
	link   string
}

// WriteArchive writes a gzip-compressed POSIX tar stream without following
// symlinks. Socket, device, and FIFO entries are rejected: restoring those
// from an untrusted workload volume would cross the container boundary.
func WriteArchive(dst io.Writer, root string) error {
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("volume root must be a directory")
	}
	gz := gzip.NewWriter(dst)
	tw := tar.NewWriter(gz)
	closeWithError := func(current error) error {
		if err := tw.Close(); current == nil {
			current = err
		}
		if err := gz.Close(); current == nil {
			current = err
		}
		return current
	}
	entries := 0
	err = filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filename == root {
			return nil
		}
		entries++
		if entries > maxArchiveEntries {
			return errors.New("volume contains too many archive entries")
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if err = validateArchiveName(name); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		var link string
		if info.Mode()&os.ModeSymlink != 0 {
			link, err = os.Readlink(filename)
			if err != nil {
				return err
			}
			if err = validateSymlink(name, filepath.ToSlash(link)); err != nil {
				return err
			}
		} else if !info.Mode().IsRegular() && !info.IsDir() {
			return fmt.Errorf("unsupported special file %q", name)
		}
		header, err := tar.FileInfoHeader(info, filepath.ToSlash(link))
		if err != nil {
			return err
		}
		header.Name = name
		if err = tw.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(tw, file, info.Size())
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	return closeWithError(err)
}

// RestoreArchive validates the complete archive before touching live data,
// extracts into a staging directory, and keeps the former tree in a rollback
// directory until every top-level rename succeeds.
func RestoreArchive(src io.Reader, root string) error {
	root = filepath.Clean(root)
	if root == "." || root == string(filepath.Separator) {
		return errors.New("unsafe volume root")
	}
	if err := validateArchive(src); err != nil {
		return err
	}
	seeker, ok := src.(io.ReadSeeker)
	if !ok {
		return errors.New("archive source must be seekable")
	}
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(root, internalPrefix+"staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err = extractArchive(seeker, staging); err != nil {
		return err
	}
	rollback, err := os.MkdirTemp(root, internalPrefix+"rollback-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(rollback)
	oldNames, err := topLevelNames(root, filepath.Base(staging), filepath.Base(rollback))
	if err != nil {
		return err
	}
	for _, name := range oldNames {
		if err = os.Rename(filepath.Join(root, name), filepath.Join(rollback, name)); err != nil {
			_ = moveNames(rollback, root, oldNames)
			return fmt.Errorf("stage existing volume data: %w", err)
		}
	}
	newNames, err := topLevelNames(staging)
	if err == nil {
		err = moveNames(staging, root, newNames)
	}
	if err != nil {
		_ = moveNames(root, staging, newNames)
		if rollbackErr := moveNames(rollback, root, oldNames); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("restore rollback failed: %w", rollbackErr))
		}
		return err
	}
	return os.RemoveAll(rollback)
}

func validateArchive(src io.Reader) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("open volume archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	symlinks := map[string]bool{}
	for entries := 0; ; entries++ {
		if entries >= maxArchiveEntries {
			return errors.New("volume archive contains too many entries")
		}
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read volume archive: %w", err)
		}
		name := strings.TrimSuffix(header.Name, "/")
		if err = validateArchiveName(name); err != nil {
			return err
		}
		if seen[name] {
			return fmt.Errorf("duplicate archive entry %q", name)
		}
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if symlinks[parent] {
				return fmt.Errorf("archive entry %q descends through symlink %q", name, parent)
			}
		}
		seen[name] = true
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeRegA, tar.TypeDir:
		case tar.TypeSymlink:
			if err = validateSymlink(name, header.Linkname); err != nil {
				return err
			}
			symlinks[name] = true
		default:
			return fmt.Errorf("unsupported archive entry type for %q", name)
		}
	}
}

func extractArchive(src io.Reader, root string) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var directories, links []archiveEntry
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(header.Name, "/")
		target := filepath.Join(root, filepath.FromSlash(name))
		switch header.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(target, 0700); err != nil {
				return err
			}
			copyHeader := *header
			directories = append(directories, archiveEntry{header: &copyHeader})
		case tar.TypeReg, tar.TypeRegA:
			if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return err
			}
			file, openErr := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fs.FileMode(header.Mode)&07777)
			if openErr != nil {
				return openErr
			}
			_, copyErr := io.CopyN(file, tr, header.Size)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if err = applyMetadata(target, header); err != nil {
				return err
			}
		case tar.TypeSymlink:
			copyHeader := *header
			links = append(links, archiveEntry{header: &copyHeader, link: header.Linkname})
		}
	}
	for _, item := range links {
		target := filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(item.header.Name, "/")))
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		if err = os.Symlink(filepath.FromSlash(item.link), target); err != nil {
			return err
		}
	}
	sort.Slice(directories, func(i, j int) bool {
		return strings.Count(directories[i].header.Name, "/") > strings.Count(directories[j].header.Name, "/")
	})
	for _, item := range directories {
		target := filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(item.header.Name, "/")))
		if err = applyMetadata(target, item.header); err != nil {
			return err
		}
	}
	return nil
}

func applyMetadata(filename string, header *tar.Header) error {
	if err := os.Chmod(filename, fs.FileMode(header.Mode)&07777); err != nil {
		return err
	}
	if err := os.Chown(filename, header.Uid, header.Gid); err != nil && !errors.Is(err, fs.ErrPermission) {
		return err
	}
	return os.Chtimes(filename, header.AccessTime, header.ModTime)
}

func validateArchiveName(name string) error {
	if name == "" || len(name) > maxArchivePath || strings.ContainsRune(name, 0) || path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
		return fmt.Errorf("unsafe archive path %q", name)
	}
	if strings.HasPrefix(strings.Split(name, "/")[0], internalPrefix) {
		return fmt.Errorf("archive path %q uses a reserved prefix", name)
	}
	return nil
}

func validateSymlink(name, target string) error {
	if target == "" || len(target) > maxArchivePath || strings.ContainsRune(target, 0) || path.IsAbs(target) {
		return fmt.Errorf("unsafe symlink target for %q", name)
	}
	resolved := path.Clean(path.Join(path.Dir(name), target))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("symlink %q escapes the volume", name)
	}
	return nil
}

func topLevelNames(root string, excluded ...string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	skip := map[string]bool{}
	for _, name := range excluded {
		skip[name] = true
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !skip[entry.Name()] {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}

func moveNames(source, destination string, names []string) error {
	for _, name := range names {
		if _, err := os.Lstat(filepath.Join(source, name)); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := os.Rename(filepath.Join(source, name), filepath.Join(destination, name)); err != nil {
			return err
		}
	}
	return nil
}
