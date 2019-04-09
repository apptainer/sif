// Copyright (c) 2018-2019, Sylabs Inc. All rights reserved.
// Copyright (c) 2018, Divya Cote <divya.cote@gmail.com> All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/sylabs/sif/pkg/sif"
)

// Dump implements 'siftool dump' sub-command
func Dump() *cobra.Command {
	return &cobra.Command{
		Use:   "dump <descriptorid> <containerfile>",
		Short: "Extract and output data objects from SIF files",
		Args:  cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseUint(args[0], 10, 32)
			if err != nil {
				return fmt.Errorf("while converting input descriptor id: %s", err)
			}

			fimg, err := sif.LoadContainer(args[1], true)
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
					if _, err := fimg.Fp.Seek(v.Fileoff, 0); err != nil {
						return fmt.Errorf("while seeking to data object: %s", err)
					}
					if _, err := io.CopyN(os.Stdout, fimg.Fp, v.Filelen); err != nil {
						return fmt.Errorf("while copying data object to stdout: %s", err)
					}

					return nil
				}
			}

			return fmt.Errorf("descriptor not in range or currently unused")
		},
		DisableFlagsInUseLine: true,
	}
}
