// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"github.com/spf13/cobra"
)

// getNew returns a command that creates a new, empty SIF image.
func (c *command) getNew() *cobra.Command {
	return &cobra.Command{
		Use:     "new <sif_path>",
		Short:   "Create SIF image",
		Long:    "Create a new, empty SIF image.",
		Example: c.opts.rootPath + " new image.sif",
		Args:    cobra.ExactArgs(1),
		PreRunE: c.initApp,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.app.New(args[0])
		},
		DisableFlagsInUseLine: true,
	}
}
