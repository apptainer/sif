// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// mountSquashFS mounts the SquashFS filesystem from path at offset into mountPath.
func mountSquashFS(ctx context.Context, offset int64, path, mountPath string, mo mountFUSEOpts) error {
	args := []string{
		"-o", fmt.Sprintf("ro,offset=%d", offset),
		filepath.Clean(path),
		filepath.Clean(mountPath),
	}
	//nolint:gosec // note (gosec exclusion) - we require callers to be able to specify squashfuse not on PATH
	cmd := exec.CommandContext(ctx, mo.squashfusePath, args...)
	cmd.Stdout = mo.stdout
	cmd.Stderr = mo.stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to mount: %w", err)
	}

	return nil
}

// mountFUSEOpts accumulates mount options.
type mountFUSEOpts struct {
	stdout         io.Writer
	stderr         io.Writer
	squashfusePath string
}

// MountFUSEOpt are used to specify mount options.
type MountFUSEOpt func(*mountFUSEOpts) error

// OptMountStdout writes standard output to w.
func OptMountFUSEStdout(w io.Writer) MountFUSEOpt {
	return func(mo *mountFUSEOpts) error {
		mo.stdout = w
		return nil
	}
}

// OptMountFUSEStderr writes standard error to w.
func OptMountFUSEStderr(w io.Writer) MountFUSEOpt {
	return func(mo *mountFUSEOpts) error {
		mo.stderr = w
		return nil
	}
}

var errSquashfusePathInvalid = errors.New("squashfuse path must be relative or absolute")

// OptMountFUSESquashfusePath sets an explicit path to the squashfuse binary. The path must be an
// absolute or relative path.
func OptMountFUSESquashfusePath(path string) MountFUSEOpt {
	return func(mo *mountFUSEOpts) error {
		if filepath.Base(path) == path {
			return errSquashfusePathInvalid
		}
		mo.squashfusePath = path
		return nil
	}
}

var errUnsupportedFSType = errors.New("unrecognized filesystem type")

// MountFUSE mounts the primary system partition of the SIF file at path into mountPath.
//
// MountFUSE may start one or more underlying processes. By default, stdout and stderr of these
// processes is discarded. To modify this behavior, consider using OptMountStdout and/or
// OptMountStderr.
//
// By default, MountFUSE searches for a squashfuse binary in the directories named by the PATH
// environment variable. To override this behavior, consider using OptMountSquashfusePath().
func MountFUSE(ctx context.Context, path, mountPath string, opts ...MountFUSEOpt) error {
	mo := mountFUSEOpts{
		squashfusePath: "squashfuse",
	}

	for _, opt := range opts {
		if err := opt(&mo); err != nil {
			return fmt.Errorf("%w", err)
		}
	}

	f, err := LoadContainerFromPath(path, OptLoadWithFlag(os.O_RDONLY))
	if err != nil {
		return fmt.Errorf("failed to load image: %w", err)
	}
	defer func() { _ = f.UnloadContainer() }()

	d, err := f.GetDescriptor(WithPartitionType(PartPrimSys))
	if err != nil {
		return fmt.Errorf("failed to get partition descriptor: %w", err)
	}

	fs, _, _, err := d.PartitionMetadata()
	if err != nil {
		return fmt.Errorf("failed to get partition metadata: %w", err)
	}

	switch fs {
	case FsSquash:
		return mountSquashFS(ctx, d.Offset(), path, mountPath, mo)
	default:
		return errUnsupportedFSType
	}
}
