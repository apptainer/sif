// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2018, Divya Cote <divya.cote@gmail.com> All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"github.com/spf13/cobra"
)

// getHeader returns a command that displays the global SIF header.
func (c *command) getHeader() *cobra.Command {
	return &cobra.Command{
		Use:     "header <sif_path>",
		Short:   "Display global header",
		Long:    "Display global header from a SIF image.",
		Example: c.opts.rootPath + " header image.sif",
		Args:    cobra.ExactArgs(1),
		PreRunE: c.initApp,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.app.Header(args[0])
		},
		DisableFlagsInUseLine: true,
	}
}
