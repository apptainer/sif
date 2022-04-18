// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"context"

	"github.com/apptainer/sif/v2/internal/pkg/exp"
)

// Unmounts the FUSE mounted filesystem at mountPath.
func (a *App) Unmount(ctx context.Context, mountPath string) error {
	return exp.Unmount(ctx, mountPath,
		exp.OptUnmountStdout(a.opts.out),
		exp.OptUnmountStderr(a.opts.err),
	)
}
