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

// getDel returns a command that deletes a data object from a SIF.
func (c *command) getDel() *cobra.Command {
	return &cobra.Command{
		Use:   "del <descriptorid> <containerfile>",
		Short: "Delete a specified object descriptor and data from SIF file",
		Args:  cobra.ExactArgs(2),

		PreRunE: c.initApp,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseUint(args[0], 10, 32)
			if err != nil {
				return fmt.Errorf("while converting input descriptor id: %s", err)
			}

			return c.app.Del(args[1], uint32(id))
		},
	}
}
