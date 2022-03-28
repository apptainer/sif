// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// Package exp contains experimental functionality that is not sufficiently mature to be exported
// as part of the module API.
package exp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/apptainer/sif/v2/pkg/sif"
)

// mountSquashFS mounts the SquashFS filesystem from path at offset into mountPath.
func mountSquashFS(ctx context.Context, offset int64, path, mountPath string, mo mountOpts) error {
	args := []string{
		"-o", fmt.Sprintf("ro,offset=%d", offset),
		filepath.Clean(path),
		filepath.Clean(mountPath),
	}

	cmd := exec.CommandContext(ctx, "squashfuse", args...)
	cmd.Stdout = mo.stdout
	cmd.Stderr = mo.stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to mount: %w", err)
	}

	return nil
}

// mountOpts accumulates mount options.
type mountOpts struct {
	stdout io.Writer
	stderr io.Writer
}

// MountOpt are used to specify mount options.
type MountOpt func(*mountOpts) error

// OptMountStdout writes standard output to w.
func OptMountStdout(w io.Writer) MountOpt {
	return func(mo *mountOpts) error {
		mo.stdout = w
		return nil
	}
}

// OptMountStderr writes standard error to w.
func OptMountStderr(w io.Writer) MountOpt {
	return func(mo *mountOpts) error {
		mo.stderr = w
		return nil
	}
}

var errUnsupportedFSType = errors.New("unrecognized filesystem type")

// Mount mounts the primary system partition of the SIF file at path into mountPath.
//
// Mount may start one or more underlying processes. By default, stdout and stderr of these
// processes is discarded. To modify this behavior, consider using OptMountStdout and/or
// OptMountStderr.
func Mount(ctx context.Context, path, mountPath string, opts ...MountOpt) error {
	mo := mountOpts{}

	for _, opt := range opts {
		if err := opt(&mo); err != nil {
			return fmt.Errorf("%w", err)
		}
	}

	f, err := sif.LoadContainerFromPath(path, sif.OptLoadWithFlag(os.O_RDONLY))
	if err != nil {
		return fmt.Errorf("failed to load image: %w", err)
	}
	defer func() { _ = f.UnloadContainer() }()

	d, err := f.GetDescriptor(sif.WithPartitionType(sif.PartPrimSys))
	if err != nil {
		return fmt.Errorf("failed to get partition descriptor: %w", err)
	}

	fs, _, _, err := d.PartitionMetadata()
	if err != nil {
		return fmt.Errorf("failed to get partition metadata: %w", err)
	}

	switch fs {
	case sif.FsSquash:
		return mountSquashFS(ctx, d.Offset(), path, mountPath, mo)
	default:
		return errUnsupportedFSType
	}
}
