// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"fmt"
	"github.com/sylabs/sif/pkg/sif"
	"strconv"
)

func cmdDel(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("while converting input descriptor id: %s", err)
	}

	fimg, err := sif.LoadContainer(args[1], false)
	if err != nil {
		return fmt.Errorf("while loading SIF file: %s", err)
	}
	defer fimg.UnloadContainer()

	for _, v := range fimg.DescrArr {
		if v.Used == false {
			continue
		} else if v.ID == uint32(id) {
			if err := fimg.DeleteObject(uint32(id), 0); err != nil {
				return fmt.Errorf("while deleting object: %s", err)
			}

			return nil
		}
	}

	return fmt.Errorf("descriptor not in range or currently unused")
}
