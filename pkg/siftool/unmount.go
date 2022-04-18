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

// getUnmount returns a command that unmounts the primary system partition of a SIF image.
func (c *command) getUnmount() *cobra.Command {
	return &cobra.Command{
		Use:     "unmount <mount_path>",
		Short:   "Unmount primary system partition",
		Long:    "Unmount a primary system partition of a SIF image",
		Example: c.opts.rootPath + " unmount path/",
		Args:    cobra.ExactArgs(1),
		PreRunE: c.initApp,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.app.Unmount(cmd.Context(), args[0])
		},
		DisableFlagsInUseLine: true,
		Hidden:                true, // hide while command is experimental
	}
}
