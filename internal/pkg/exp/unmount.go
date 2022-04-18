// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package exp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
)

// unmountSquashFS unmounts the filesystem at mountPath.
func unmountSquashFS(ctx context.Context, mountPath string, uo unmountOpts) error {
	args := []string{
		"-u",
		filepath.Clean(mountPath),
	}
	cmd := exec.CommandContext(ctx, uo.fusermountPath, args...) //nolint:gosec
	cmd.Stdout = uo.stdout
	cmd.Stderr = uo.stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to unmount: %w", err)
	}

	return nil
}

// unmountOpts accumulates unmount options.
type unmountOpts struct {
	stdout         io.Writer
	stderr         io.Writer
	fusermountPath string
}

// UnmountOpt are used to specify unmount options.
type UnmountOpt func(*unmountOpts) error

// OptUnmountStdout writes standard output to w.
func OptUnmountStdout(w io.Writer) UnmountOpt {
	return func(mo *unmountOpts) error {
		mo.stdout = w
		return nil
	}
}

// OptUnmountStderr writes standard error to w.
func OptUnmountStderr(w io.Writer) UnmountOpt {
	return func(mo *unmountOpts) error {
		mo.stderr = w
		return nil
	}
}

var errFusermountPathInvalid = errors.New("fusermount path must be relative or absolute")

// OptUnmountFusermountPath sets the path to the fusermount binary.
func OptUnmountFusermountPath(path string) UnmountOpt {
	return func(mo *unmountOpts) error {
		if filepath.Base(path) == path {
			return errFusermountPathInvalid
		}
		mo.fusermountPath = path
		return nil
	}
}

// Unmount the FUSE mounted filesystem at mountPath.
//
// Unmount may start one or more underlying processes. By default, stdout and stderr of these
// processes is discarded. To modify this behavior, consider using OptUnmountStdout and/or
// OptUnmountStderr.
//
// By default, Unmount searches for a fusermount binary in the directories named by the PATH
// environment variable. To override this behavior, consider using OptUnmountFusermountPath().
func Unmount(ctx context.Context, mountPath string, opts ...UnmountOpt) error {
	uo := unmountOpts{
		fusermountPath: "fusermount",
	}

	for _, opt := range opts {
		if err := opt(&uo); err != nil {
			return fmt.Errorf("%w", err)
		}
	}

	return unmountSquashFS(ctx, mountPath, uo)
}
