// Copyright (c) 2018, Divya Cote <divya.cote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"fmt"
	"strconv"

	"github.com/hpcng/sif/internal/app/siftool"
)

// cmdHeader displays a SIF file global header to stdout.
func cmdHeader(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage")
	}

	return siftool.Header(args[0])
}

// cmdList displays a list of all active descriptors from a SIF file to stdout.
func cmdList(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage")
	}

	return siftool.List(args[0])
}

// cmdInfo displays detailed info about a descriptor from a SIF file to stdout.
func cmdInfo(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("while converting input descriptor id: %s", err)
	}

	return siftool.Info(id, args[1])
}

// cmdDump extracts and output a data object from a SIF file to stdout.
func cmdDump(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("while converting input descriptor id: %s", err)
	}

	return siftool.Dump(id, args[1])
}
