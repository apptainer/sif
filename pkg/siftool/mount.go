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
	"github.com/spf13/cobra"
)

// getMount returns a command that mounts the primary system partition of a SIF image.
func (c *command) getMount() *cobra.Command {
	return &cobra.Command{
		Use:     "mount <sif_path> <mount_path>",
		Short:   "Mount primary system partition",
		Long:    "Mount the primary system partition of a SIF image",
		Example: c.opts.rootPath + " mount image.sif path/",
		Args:    cobra.ExactArgs(2),
		PreRunE: c.initApp,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.app.Mount(cmd.Context(), args[0], args[1])
		},
		DisableFlagsInUseLine: true,
		Hidden:                true, // hide while command is experimental
	}
}
