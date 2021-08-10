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
func getSetPrim(co commandOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "setprim <descriptorid> <containerfile>",
		Short: "Set primary system partition",
		Args:  cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseUint(args[0], 10, 32)
			if err != nil {
				return fmt.Errorf("while converting input descriptor id: %s", err)
			}

			return co.app.Setprim(args[1], uint32(id))
		},
	}
}
