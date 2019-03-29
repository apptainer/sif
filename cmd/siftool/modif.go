// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	uuid "github.com/satori/go.uuid"
	"github.com/sylabs/sif/pkg/sif"
)

var datatype = flag.Int64("datatype", -1, "")
var parttype = flag.Int64("parttype", -1, "")
var partfs = flag.Int64("partfs", -1, "")
var partarch = flag.Int64("partarch", -1, "")
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

	cinfo := sif.CreateInfo{
		Pathname:   args[0],
		Launchstr:  sif.HdrLaunch,
		Sifversion: sif.HdrVersion,
		ID:         uuid.NewV4(),
	}

	_, err := sif.CreateContainer(cinfo)
	if err != nil {
		return err
	}

	return nil
}

func cmdAdd(args []string) error {
	var err error
	var d sif.Datatype
	var a string

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
	case 7:
		d = sif.DataGeneric
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
		fp, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer fp.Close()

		input.Fp = fp

		fi, err := fp.Stat()
		if err != nil {
			return err
		}
		input.Size = fi.Size()
	}

	if d == sif.DataPartition {
		if sif.Fstype(*partfs) == -1 || sif.Parttype(*parttype) == -1 || *partarch == -1 {
			return fmt.Errorf("with partition datatype, -partfs, -parttype and -partarch must be passed")
		}

		switch *partarch {
		case 1:
			a = sif.HdrArch386
		case 2:
			a = sif.HdrArchAMD64
		case 3:
			a = sif.HdrArchARM
		case 4:
			a = sif.HdrArchARM64
		case 5:
			a = sif.HdrArchPPC64
		case 6:
			a = sif.HdrArchPPC64le
		case 7:
			a = sif.HdrArchMIPS
		case 8:
			a = sif.HdrArchMIPSle
		case 9:
			a = sif.HdrArchMIPS64
		case 10:
			a = sif.HdrArchMIPS64le
		case 11:
			a = sif.HdrArchS390x
		default:
			log.Printf("error: -partarch flag is required with a valid range\n\n")
			return fmt.Errorf("usage")
		}

		err := input.SetPartExtra(sif.Fstype(*partfs), sif.Parttype(*parttype), a)
		if err != nil {
			return err
		}
	} else if d == sif.DataSignature {
		if sif.Hashtype(*signhash) == -1 || *signentity == "" {
			return fmt.Errorf("with signature datatype, -signhash and -signentity must be passed")
		}

		if err := input.SetSignExtra(sif.Hashtype(*signhash), *signentity); err != nil {
			return err
		}
	}

	// load SIF image file
	fimg, err := sif.LoadContainer(args[0], false)
	if err != nil {
		return err
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			fmt.Println("Error unloading container: ", err)
		}
	}()

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
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			fmt.Println("Error unloading container: ", err)
		}
	}()

	for _, v := range fimg.DescrArr {
		if !v.Used {
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

func cmdSetPrim(args []string) error {
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
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			fmt.Println("Error unloading container: ", err)
		}
	}()

	for _, v := range fimg.DescrArr {
		if !v.Used {
			continue
		} else if v.ID == uint32(id) {
			if err := fimg.SetPrimPart(uint32(id)); err != nil {
				return err
			}

			return nil
		}
	}

	return fmt.Errorf("descriptor not in range or currently unused")
}
