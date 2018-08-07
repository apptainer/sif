// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/satori/go.uuid"
	"github.com/sylabs/sif/pkg/sif"
	"log"
	"os"
	"runtime"
	"strconv"
)

var datatype = flag.Int64("datatype", -1, "")
var parttype = flag.Int64("parttype", -1, "")
var partfs = flag.Int64("partfs", -1, "")
var signhash = flag.Int64("signhash", -1, "")
var signentity = flag.String("signentity", "", "")
var groupid = flag.Int64("groupid", sif.DescrUnusedGroup, "")
var link = flag.Int64("link", sif.DescrUnusedLink, "")
var alignment = flag.Int("alignment", 0, "")
var filename = flag.String("filename", "", "")

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
	var err error
	var d sif.Datatype

	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	switch *datatype {
	case 1:
		d = sif.DataDeffile
	case 2:
		d = sif.DataEnvVar
	case 3:
		d = sif.DataLabels
	case 4:
		d = sif.DataPartition
	case 5:
		d = sif.DataSignature
	case 6:
		d = sif.DataGenericJSON
	default:
		log.Printf("error: -datatype flag is required with a valid range\n\n")
		return fmt.Errorf("usage")
	}

	if *filename == "" {
		*filename = args[1]
	}

	// data we need to create a new descriptor
	input := sif.DescriptorInput{
		Datatype:  d,
		Groupid:   sif.DescrGroupMask | uint32(*groupid),
		Link:      uint32(*link),
		Alignment: *alignment,
		Fname:     *filename,
	}

	if args[1] == "-" {
		input.Fp = os.Stdin
	} else {
		// open up the data object file for this descriptor
		if input.Fp, err = os.Open(args[1]); err != nil {
			return err
		}
		defer input.Fp.Close()

		fi, err := input.Fp.Stat()
		if err != nil {
			return err
		}
		input.Size = fi.Size()
	}

	if d == sif.DataPartition {
		if int32(*partfs) == -1 || int32(*parttype) == -1 {
			return fmt.Errorf("with partition datatype, -partfs and -parttype must be passed")
		}

		// extra data needed for the creation of a partition descriptor
		extra := sif.Partition{
			Fstype:   sif.Fstype(*partfs),
			Parttype: sif.Parttype(*parttype),
		}

		// serialize the partition data for integration with the base descriptor input
		if err := binary.Write(&input.Extra, binary.LittleEndian, extra); err != nil {
			return err
		}
	} else if d == sif.DataSignature {
		if int32(*signhash) == -1 || *signentity == "" {
			return fmt.Errorf("with signature datatype, -signhash and -signentity must be passed")
		}

		// extra data needed for the creation of a signature descriptor
		extra := sif.Signature{
			Hashtype: sif.Hashtype(*signhash),
		}
		h, err := hex.DecodeString(*signentity)
		if err != nil {
			return err
		}
		copy(extra.Entity[:], h)

		// serialize the partition data for integration with the base descriptor input
		if err := binary.Write(&input.Extra, binary.LittleEndian, extra); err != nil {
			return err
		}
	}

	// load SIF image file
	fimg, err := sif.LoadContainer(args[0], false)
	if err != nil {
		return err
	}
	defer fimg.UnloadContainer()

	// add new data object to SIF file
	if err = fimg.AddObject(input); err != nil {
		return err
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
