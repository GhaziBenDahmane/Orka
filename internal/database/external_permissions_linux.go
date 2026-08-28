package database

import (
	"errors"
	"os"
	"syscall"
)

func validateDriverOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("must be owned by the controller user")
	}
	return nil
}

func openTrustedDriver(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0) {
		err = errors.New("must be a regular executable file")
	}
	if err == nil && info.Mode().Perm()&0022 != 0 {
		err = errors.New("must not be group/world writable")
	}
	if err == nil {
		err = validateDriverOwner(info)
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
