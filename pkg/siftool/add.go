// Copyright (c) 2019, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/sylabs/sif/pkg/sif"
)

// Add implements 'siftool add' sub-command
func Add() *cobra.Command {
	ret := &cobra.Command{
		Use:   "add [OPTIONS] <containerfile> <dataobjectfile>",
		Short: "Add a data object to a SIF file",
		Args:  cobra.ExactArgs(2),
	}

	opts := addOpts{
		datatype: ret.Flags().Int64("datatype", -1, `the type of data to add
[NEEDED, no default]:
  1-Deffile,   2-EnvVar,    3-Labels,
  4-Partition, 5-Signature, 6-GenericJSON`),
		parttype: ret.Flags().Int64("parttype", -1, `the type of parition (with -datatype 4-Partition)
[NEEDED, no default]:
  1-System,    2-PrimSys,   3-Data,
  4-Overlay`),
		partfs: ret.Flags().Int64("partfs", -1, `the filesystem used (with -datatype 4-Partition)
[NEEDED, no default]:
  1-Squash,    2-Ext3,      3-ImmuObj,
  4-Raw`),
		partarch: ret.Flags().Int64("partarch", -1, `the main architecture used (with -datatype 4-Partition)
[NEEDED, no default]:
  1-386,       2-amd64,     3-arm,
  4-arm64,     5-ppc64,     6-ppc64le,
  7-mips,      8-mipsle,    9-mips64,
  10-mips64le, 11-s390x`),
		signhash: ret.Flags().Int64("signhash", -1, `the signature hash used (with -datatype 5-Signature)
[NEEDED, no default]:
  1-SHA256,    2-SHA384,    3-SHA512,
  4-BLAKE2S,   5-BLAKE2B`),
		signentity: ret.Flags().String("signentity", "", `the entity that signs (with -datatype 5-Signature)
[NEEDED, no default]:
  example: 433FE984155206BD962725E20E8713472A879943`),
		groupid:   ret.Flags().Int64("groupid", sif.DescrUnusedGroup, "set groupid [default: DescrUnusedGroup]"),
		link:      ret.Flags().Int64("link", sif.DescrUnusedLink, "set link pointer [default: DescrUnusedLink]"),
		alignment: ret.Flags().Int("alignment", 0, "set alignment constraint [default: aligned on page size]"),
		filename:  ret.Flags().String("filename", "", "set logical filename/handle [default: input filename]"),
	}

	ret.RunE = func(cmd *cobra.Command, args []string) error {
		return addFn(args, opts)
	}

	// function to set flag.DefVal to the "zero-value"
	fn := func(name, setdef string) {
		fl := ret.Flags().Lookup(name)
		if fl == nil {
			return
		}

		fl.DefValue = setdef
	}

	// set the DefVal fields for all the siftool add flags
	fn("datatype", "0")
	fn("parttype", "0")
	fn("partfs", "0")
	fn("partarch", "0")
	fn("signhash", "0")
	fn("signentity", "")
	fn("groupid", "0")
	fn("link", "0")
	fn("alignment", "0")

	return ret
}

type addOpts struct {
	datatype   *int64
	parttype   *int64
	partfs     *int64
	partarch   *int64
	signhash   *int64
	signentity *string
	groupid    *int64
	link       *int64
	alignment  *int
	filename   *string
}

func addFn(args []string, opts addOpts) error {
	var err error
	var d sif.Datatype
	var a string

	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	switch *opts.datatype {
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

	if *opts.filename == "" {
		*opts.filename = args[1]
	}

	// data we need to create a new descriptor
	input := sif.DescriptorInput{
		Datatype:  d,
		Groupid:   sif.DescrGroupMask | uint32(*opts.groupid),
		Link:      uint32(*opts.link),
		Alignment: *opts.alignment,
		Fname:     *opts.filename,
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
		if sif.Fstype(*opts.partfs) == -1 || sif.Parttype(*opts.parttype) == -1 || *opts.partarch == -1 {
			return fmt.Errorf("with partition datatype, -partfs, -parttype and -partarch must be passed")
		}

		switch *opts.partarch {
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

		err := input.SetPartExtra(sif.Fstype(*opts.partfs), sif.Parttype(*opts.parttype), a)
		if err != nil {
			return err
		}
	} else if d == sif.DataSignature {
		if sif.Hashtype(*opts.signhash) == -1 || *opts.signentity == "" {
			return fmt.Errorf("with signature datatype, -signhash and -signentity must be passed")
		}

		if err := input.SetSignExtra(sif.Hashtype(*opts.signhash), *opts.signentity); err != nil {
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
