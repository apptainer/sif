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

// getList returns a command that lists object descriptors from a SIF image.
func (c *command) getList() *cobra.Command {
	return &cobra.Command{
		Use:     "list <sif_path>",
		Short:   "List data objects",
		Long:    "List data objects from a SIF image.",
		Example: c.opts.rootPath + " list image.sif",
		Args:    cobra.ExactArgs(1),
		PreRunE: c.initApp,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.app.List(args[0])
		},
		DisableFlagsInUseLine: true,
	}
}
