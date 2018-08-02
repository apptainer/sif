// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"fmt"
	"github.com/satori/go.uuid"
	"github.com/sylabs/sif/pkg/sif"
	"runtime"
	"strconv"
)

func cmdNew(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage")
	}

	archMap := map[string]string{
		"386":      sif.HdrArch386,
		"amd64":    sif.HdrArchAMD64,
		"arm":      sif.HdrArchARM,
		"arm64":    sif.HdrArchARM64,
		"ppc64":    sif.HdrArchPPC64,
		"ppc64le":  sif.HdrArchPPC64le,
		"mips":     sif.HdrArchMIPS,
		"mipsle":   sif.HdrArchMIPSle,
		"mips64":   sif.HdrArchMIPS64,
		"mips64le": sif.HdrArchMIPS64le,
		"s390x":    sif.HdrArchS390x,
	}

	// determine HdrArch value based on GOARCH
	arch, ok := archMap[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("GOARCH %v not supported", runtime.GOARCH)
	}

	cinfo := sif.CreateInfo{
		Pathname:   args[0],
		Launchstr:  sif.HdrLaunch,
		Sifversion: sif.HdrVersion,
		Arch:       arch,
		ID:         uuid.NewV4(),
	}

	err := sif.CreateContainer(cinfo)
	if err != nil {
		return err
	}

	return nil
}

func cmdAdd(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}
	return nil
}

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
		return err
	}
	defer fimg.UnloadContainer()

	for _, v := range fimg.DescrArr {
		if v.Used == false {
			continue
		} else if v.ID == uint32(id) {
			if err := fimg.DeleteObject(uint32(id), 0); err != nil {
				return err
			}

			return nil
		}
	}

	return fmt.Errorf("descriptor not in range or currently unused")
}
