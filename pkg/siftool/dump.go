// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2018, Divya Cote <divya.cote@gmail.com> All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

// getDump returns a command that dumps a data object from a SIF file.
func (c *command) getDump() *cobra.Command {
	return &cobra.Command{
		Use:     "dump <id> <sif_path>",
		Short:   "Dump data object",
		Long:    "Dump a data object from a SIF image.",
		Example: c.opts.rootPath + " dump 1 image.sif",
		Args:    cobra.ExactArgs(2),
		PreRunE: c.initApp,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseUint(args[0], 10, 32)
			if err != nil {
				return fmt.Errorf("while converting id: %w", err)
			}

			return c.app.Dump(args[1], uint32(id))
		},
		DisableFlagsInUseLine: true,
	}
}
