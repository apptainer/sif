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
	"time"

	"github.com/spf13/cobra"
	"github.com/sylabs/sif/pkg/sif"
)

// List implements 'siftool list' sub-command
func List() *cobra.Command {
	return &cobra.Command{
		Use:   "list <containerfile>",
		Short: "List object descriptors from SIF files",
		Args:  cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			fimg, err := sif.LoadContainer(args[0], true)
			if err != nil {
				return err
			}
			defer func() {
				if err := fimg.UnloadContainer(); err != nil {
					fmt.Println("Error unloading container: ", err)
				}
			}()

			fmt.Println("Container id:", fimg.Header.ID)
			fmt.Println("Created on:  ", time.Unix(fimg.Header.Ctime, 0))
			fmt.Println("Modified on: ", time.Unix(fimg.Header.Mtime, 0))
			fmt.Println("----------------------------------------------------")

			fmt.Println("Descriptor list:")

			fmt.Print(fimg.FmtDescrList())

			return nil
		},
		DisableFlagsInUseLine: true,
	}
}
