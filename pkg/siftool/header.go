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

	"github.com/spf13/cobra"
	"github.com/sylabs/sif/pkg/sif"
)

// Header implements 'siftool header' sub-command
func Header() *cobra.Command {
	return &cobra.Command{
		Use:   "header <containerfile>",
		Short: "Display SIF global headers",
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

			fmt.Print(fimg.FmtHeader())

			return nil
		},
		DisableFlagsInUseLine: true,
	}
}
