// Copyright (c) 2018-019, Sylabs Inc. All rights reserved.
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
	"github.com/sylabs/sif/pkg/sif"
)

// Del implements 'siftool del' sub-command
func Del() *cobra.Command {
	return &cobra.Command{
		Use:   "del <descriptorid> <containerfile>",
		Short: "Delete a specified object descriptor and data from SIF file",
		Args:  cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseUint(args[0], 10, 32)
			if err != nil {
				return fmt.Errorf("while converting input descriptor id: %s", err)
			}

			fimg, err := sif.LoadContainer(args[1], false)
			if err != nil {
				return err
			}
			defer func() {
				if err := fimg.UnloadContainer(); err != nil {
					fmt.Println("Error unloading container: ", err)
				}
			}()

			for _, v := range fimg.DescrArr {
				if !v.Used {
					continue
				} else if v.ID == uint32(id) {
					if err := fimg.DeleteObject(uint32(id), 0); err != nil {
						return err
					}

					return nil
				}
			}

			return fmt.Errorf("descriptor not in range or currently unused")
		},
	}
}
