// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/hpcng/sif/internal/app/siftool"
	"github.com/hpcng/sif/pkg/sif" //nolint:staticcheck // In use until v2 API
)

var (
	datatype   = flag.Int("datatype", 0, "")
	parttype   = flag.Int("parttype", 0, "")
	partfs     = flag.Int("partfs", 0, "")
	partarch   = flag.Int("partarch", 0, "")
	signhash   = flag.Int("signhash", 0, "")
	signentity = flag.String("signentity", "", "")
	groupid    = flag.Int("groupid", 0, "")
	link       = flag.Int("link", 0, "")
	alignment  = flag.Int("alignment", 0, "")
	filename   = flag.String("filename", "", "")
)

func cmdNew(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage")
	}

	return siftool.New(args[0])
}

func cmdAdd(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	opts := siftool.AddOptions{
		Groupid:   uint32(*groupid),
		Link:      uint32(*link),
		Alignment: *alignment,
		Filename:  *filename,
		Fp:        os.Stdin,
	}

	switch *datatype {
	case 1:
		opts.Datatype = sif.DataDeffile
	case 2:
		opts.Datatype = sif.DataEnvVar
	case 3:
		opts.Datatype = sif.DataLabels
	case 4:
		opts.Datatype = sif.DataPartition
	case 5:
		opts.Datatype = sif.DataSignature
	case 6:
		opts.Datatype = sif.DataGenericJSON
	case 7:
		opts.Datatype = sif.DataGeneric
	case 8:
		opts.Datatype = sif.DataCryptoMessage
	default:
		return errors.New("-datatype flag is required with a valid range")
	}

	if opts.Datatype == sif.DataPartition {
		if *partfs == 0 || *parttype == 0 || *partarch == 0 {
			return errors.New("with partition datatype, -partfs, -parttype and -partarch must be passed")
		}

		opts.Parttype = sif.Parttype(*parttype)
		opts.Partfs = sif.Fstype(*partfs)

		switch *partarch {
		case 1:
			opts.Partarch = sif.HdrArch386
		case 2:
			opts.Partarch = sif.HdrArchAMD64
		case 3:
			opts.Partarch = sif.HdrArchARM
		case 4:
			opts.Partarch = sif.HdrArchARM64
		case 5:
			opts.Partarch = sif.HdrArchPPC64
		case 6:
			opts.Partarch = sif.HdrArchPPC64le
		case 7:
			opts.Partarch = sif.HdrArchMIPS
		case 8:
			opts.Partarch = sif.HdrArchMIPSle
		case 9:
			opts.Partarch = sif.HdrArchMIPS64
		case 10:
			opts.Partarch = sif.HdrArchMIPS64le
		case 11:
			opts.Partarch = sif.HdrArchS390x
		default:
			return errors.New("-partarch flag is required with a valid range")
		}
	} else if opts.Datatype == sif.DataSignature {
		if *signhash == 0 || *signentity == "" {
			return errors.New("with signature datatype, -signhash and -signentity must be passed")
		}

		opts.Signhash = sif.Hashtype(*signhash)
		opts.Signentity = *signentity
	}

	if dataFile := args[1]; dataFile != "-" {
		fp, err := os.Open(dataFile)
		if err != nil {
			return err
		}
		defer fp.Close()

		opts.Fp = fp

		if opts.Filename == "" {
			opts.Filename = dataFile
		}
	}

	return siftool.Add(args[0], opts)
}

func cmdDel(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("while converting input descriptor id: %s", err)
	}

	return siftool.Del(args[1], uint32(id))
}

func cmdSetPrim(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("while converting input descriptor id: %s", err)
	}

	return siftool.Setprim(args[0], uint32(id))
}
