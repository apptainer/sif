// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
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

// getSetPrim returns a command that sets the primary system partition.
func (c *command) getSetPrim() *cobra.Command {
	return &cobra.Command{
		Use:     "setprim <id> <sif_path>",
		Short:   "Set primary system partition",
		Long:    "Set the primary system partition in a SIF image.",
		Example: c.opts.rootPath + " setprim 1 image.sif",
		Args:    cobra.ExactArgs(2),
		PreRunE: c.initApp,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseUint(args[0], 10, 32)
			if err != nil {
				return fmt.Errorf("while converting id: %w", err)
			}

			return c.app.Setprim(args[1], uint32(id))
		},
		DisableFlagsInUseLine: true,
	}
}
