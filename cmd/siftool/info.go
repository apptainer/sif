// Copyright (c) 2018, Divya Cote <divya.cote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"fmt"
	"github.com/sylabs/sif/pkg/sif"
)

// cmdHeader displays a SIF file global header to stdout
func cmdHeader(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage")
	}

	fimg, err := sif.LoadContainer(args[0], true)
	if err != nil {
		return fmt.Errorf("while loading SIF file: %s", err)
	}
	defer fimg.UnloadContainer()

	return nil
}

// cmdList displays a list of all active descriptors from a SIF file to stdout
func cmdList(args []string) error {
	return nil
}

// cmdInfo displays detailed info about a descriptor from a SIF file to stdout
func cmdInfo(args []string) error {
	return nil
}

// cmdDump extracts and output a data object from a SIF file to stdout
func cmdDump(args []string) error {
	return nil
}
