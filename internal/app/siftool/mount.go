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

	"github.com/apptainer/sif/v2/pkg/user"
)

// Mount mounts the primary system partition of the SIF file at path into mountPath.
func (a *App) Mount(ctx context.Context, path, mountPath string) error {
	return user.Mount(ctx, path, mountPath,
		user.OptMountStdout(a.opts.out),
		user.OptMountStderr(a.opts.err),
	)
}
