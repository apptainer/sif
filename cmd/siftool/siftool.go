// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2018-2024, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"text/tabwriter"

	"github.com/apptainer/sif/v2/pkg/sif"
	"github.com/apptainer/sif/v2/pkg/siftool"
	"github.com/spf13/cobra"
)

var (
	version = "unknown"
	date    = ""
	builtBy = ""
	commit  = ""
)

func writeVersion(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	defer tw.Flush()

	fmt.Fprintf(tw, "Version:\t%v\n", version)

	if builtBy != "" {
		fmt.Fprintf(tw, "By:\t%v\n", builtBy)
	}

	if commit != "" {
		fmt.Fprintf(tw, "Commit:\t%v\n", commit)
	}

	if date != "" {
		fmt.Fprintf(tw, "Date:\t%v\n", date)
	}

	fmt.Fprintf(tw, "Runtime:\t%v (%v/%v)\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(tw, "Spec:\t%v\n", sif.CurrentVersion)

	return nil
}

func getVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display version information",
		Long:  "Display binary version, build info and compatible SIF version(s).",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return writeVersion(cmd.OutOrStdout())
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

	root.AddCommand(getVersion())

	var experimental bool
	if val, ok := os.LookupEnv("SIFTOOL_EXPERIMENTAL"); ok {
		b, err := strconv.ParseBool(val)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error: failed to parse SIFTOOL_EXPERIMENTAL environment variable:", err)
		}
		experimental = b
	}

	if err := siftool.AddCommands(&root, siftool.OptWithExperimental(experimental)); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
