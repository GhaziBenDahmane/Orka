package deploy

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	MaxArchiveSize         = 25 << 20
	MaxArchiveEntries      = 10_000
	MaxArchiveEntrySize    = 100 << 20
	MaxArchiveExpandedSize = 250 << 20
)

type archiveEntry struct {
	file *zip.File
	name string
	dir  bool
}

// ValidateArchive fully reads every entry, which validates CRCs in addition to
// checking paths, types, counts, and expansion limits before encrypted storage.
func ValidateArchive(data []byte) error {
	_, err := inspectArchive(data, true)
	return err
}

// ExtractArchive expands a previously validated archive into an empty private
// directory. A single wrapping directory is removed, matching Dokploy drops.
func ExtractArchive(data []byte, destination string) error {
	entries, err := inspectArchive(data, false)
	if err != nil {
		return err
	}
	if info, statErr := os.Stat(destination); statErr != nil || !info.IsDir() {
		return errors.New("archive destination must be an existing directory")
	}
	var expanded int64
	for _, entry := range entries {
		if entry.name == "" {
			continue
		}
		target := filepath.Join(destination, filepath.FromSlash(entry.name))
		if entry.dir {
			if err = os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err = os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		input, openErr := entry.file.Open()
		if openErr != nil {
			return openErr
		}
		permissions := entry.file.Mode().Perm()
		if permissions == 0 {
			permissions = 0o644
		}
		output, createErr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, permissions)
		if createErr != nil {
			input.Close()
			return createErr
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, MaxArchiveEntrySize+1))
		closeErr := output.Close()
		inputErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if inputErr != nil {
			return inputErr
		}
		if written != int64(entry.file.UncompressedSize64) || written > MaxArchiveEntrySize {
			return fmt.Errorf("ZIP entry %q has an invalid expanded size", entry.file.Name)
		}
		expanded += written
		if expanded > MaxArchiveExpandedSize {
			return fmt.Errorf("ZIP archive expands beyond %d MiB", MaxArchiveExpandedSize>>20)
		}
	}
	return nil
}

func inspectArchive(data []byte, readContents bool) ([]archiveEntry, error) {
	if len(data) == 0 || len(data) > MaxArchiveSize {
		return nil, fmt.Errorf("ZIP archive must be between 1 byte and %d MiB", MaxArchiveSize>>20)
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.New("uploaded file is not a valid ZIP archive")
	}
	if len(reader.File) == 0 || len(reader.File) > MaxArchiveEntries {
		return nil, fmt.Errorf("ZIP archive must contain between 1 and %d entries", MaxArchiveEntries)
	}
	seen := make(map[string]bool, len(reader.File))
	var total uint64
	entries := make([]archiveEntry, 0, len(reader.File))
	root := ""
	stripRoot := true
	files := 0
	for _, file := range reader.File {
		name, dir, cleanErr := cleanArchivePath(file)
		if cleanErr != nil {
			return nil, cleanErr
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("ZIP archive contains duplicate path %q", name)
		}
		seen[name] = dir
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if isDir, ok := seen[parent]; ok && !isDir {
				return nil, fmt.Errorf("ZIP path %q is nested below a file", name)
			}
		}
		if !dir {
			files++
			if file.UncompressedSize64 > MaxArchiveEntrySize {
				return nil, fmt.Errorf("ZIP entry %q exceeds %d MiB", name, MaxArchiveEntrySize>>20)
			}
			total += file.UncompressedSize64
			if total > MaxArchiveExpandedSize {
				return nil, fmt.Errorf("ZIP archive expands beyond %d MiB", MaxArchiveExpandedSize>>20)
			}
			parts := strings.Split(name, "/")
			if len(parts) < 2 {
				stripRoot = false
			} else if root == "" {
				root = parts[0]
			} else if root != parts[0] {
				stripRoot = false
			}
		}
		entries = append(entries, archiveEntry{file: file, name: name, dir: dir})
	}
	if files == 0 {
		return nil, errors.New("ZIP archive does not contain any files")
	}
	for name := range seen {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if isDir, exists := seen[parent]; exists && !isDir {
				return nil, fmt.Errorf("ZIP path %q conflicts with file %q", name, parent)
			}
		}
	}
	if stripRoot {
		for name := range seen {
			if name != root && !strings.HasPrefix(name, root+"/") {
				stripRoot = false
				break
			}
		}
	}
	if stripRoot && root != "" {
		prefix := root + "/"
		for i := range entries {
			if entries[i].name == root {
				entries[i].name = ""
			} else {
				entries[i].name = strings.TrimPrefix(entries[i].name, prefix)
			}
		}
	}
	if readContents {
		var expanded int64
		for _, entry := range entries {
			if entry.dir {
				continue
			}
			input, openErr := entry.file.Open()
			if openErr != nil {
				return nil, openErr
			}
			limit := int64(MaxArchiveEntrySize + 1)
			if remaining := int64(MaxArchiveExpandedSize+1) - expanded; remaining < limit {
				limit = remaining
			}
			written, copyErr := io.Copy(io.Discard, io.LimitReader(input, limit))
			closeErr := input.Close()
			if copyErr != nil || closeErr != nil || written != int64(entry.file.UncompressedSize64) {
				return nil, fmt.Errorf("ZIP entry %q is corrupt", entry.file.Name)
			}
			expanded += written
			if expanded > MaxArchiveExpandedSize {
				return nil, fmt.Errorf("ZIP archive expands beyond %d MiB", MaxArchiveExpandedSize>>20)
			}
		}
	}
	return entries, nil
}

func cleanArchivePath(file *zip.File) (string, bool, error) {
	name := file.Name
	firstComponent := strings.SplitN(name, "/", 2)[0]
	if name == "" || len(name) > 4096 || strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || strings.Contains(firstComponent, ":") {
		return "", false, fmt.Errorf("ZIP entry has unsafe path %q", name)
	}
	for _, component := range strings.Split(strings.TrimSuffix(name, "/"), "/") {
		if len(component) > 255 {
			return "", false, fmt.Errorf("ZIP entry has an oversized path component")
		}
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != strings.TrimSuffix(name, "/") {
		return "", false, fmt.Errorf("ZIP entry has unsafe path %q", name)
	}
	if file.Flags&1 != 0 {
		return "", false, fmt.Errorf("encrypted ZIP entry %q is not supported", name)
	}
	mode := file.Mode()
	dir := file.FileInfo().IsDir()
	if !dir && !mode.IsRegular() {
		return "", false, fmt.Errorf("ZIP entry %q is not a regular file", name)
	}
	if dir && mode&os.ModeType != os.ModeDir {
		return "", false, fmt.Errorf("ZIP entry %q has an invalid type", name)
	}
	return clean, dir, nil
}
