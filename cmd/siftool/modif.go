// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"fmt"
	"strconv"

	"github.com/sylabs/sif/pkg/sif"
)

// cmdDel deletes a descriptor based on its ID from a SIF file
func cmdDel(args []string) error {
	objectID, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("Error while reading object ID:\t%s", err)
	}

	// load the SIF container
	fimg, err := sif.LoadContainer(args[1], false)
	if err != nil {
		return fmt.Errorf("LoadContainer(%s, false): %s", args[1], err)
	}

	// data object deletation
	if err := fimg.DeleteObject(uint32(objectID), sif.DelZero); err != nil {
		return fmt.Errorf("fimg.DeleteObject(1, DelZero):\t%s", err)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		return fmt.Errorf("UnloadContainer(fimg):\t%s", err)
	}

	return nil
}
