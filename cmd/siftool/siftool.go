// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"os"
	"runtime"

	"github.com/hpcng/sif/v2/pkg/sif"
	"github.com/hpcng/sif/v2/pkg/siftool"
	"github.com/spf13/cobra"
)

var version = "unknown"

func getVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("siftool version %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
			cmd.Printf("SIF spec versions supported: <= %s\n", sif.HdrVersion)
		},
		DisableFlagsInUseLine: true,
	}
}

func main() {
	root := cobra.Command{
		Use:   "siftool",
		Short: "siftool is a program for Singularity Image Format (SIF) file manipulation",
		Long: `A set of commands are provided to display elements such as the SIF global
header, the data object descriptors and to dump data objects. It is also
possible to modify a SIF file via this tool via the add/del commands.`,
	}

	root.AddCommand(
		getVersion(),
		siftool.Header(),
		siftool.List(),
		siftool.Info(),
		siftool.Dump(),
		siftool.New(),
		siftool.Add(),
		siftool.Del(),
		siftool.Setprim(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
