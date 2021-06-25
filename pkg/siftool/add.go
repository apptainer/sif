// Copyright (c) 2019-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"errors"
	"os"

	"github.com/hpcng/sif/v2/internal/app/siftool"
	"github.com/hpcng/sif/v2/pkg/sif"
	"github.com/spf13/cobra"
)

// getAdd returns a command that adds a data object to a SIF.
func (c *command) getAdd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <containerfile> <dataobjectfile>",
		Short: "Add a data object to a SIF file",
		Args:  cobra.ExactArgs(2),
	}

	datatype := cmd.Flags().Int("datatype", 0, `the type of data to add
[NEEDED, no default]:
  1-Deffile,   2-EnvVar,    3-Labels,
  4-Partition, 5-Signature, 6-GenericJSON`)
	parttype := cmd.Flags().Int32("parttype", 0, `the type of partition (with -datatype 4-Partition)
[NEEDED, no default]:
  1-System,    2-PrimSys,   3-Data,
  4-Overlay`)
	partfs := cmd.Flags().Int32("partfs", 0, `the filesystem used (with -datatype 4-Partition)
[NEEDED, no default]:
  1-Squash,    2-Ext3,      3-ImmuObj,
  4-Raw`)
	partarch := cmd.Flags().Int32("partarch", 0, `the main architecture used (with -datatype 4-Partition)
[NEEDED, no default]:
  1-386,       2-amd64,     3-arm,
  4-arm64,     5-ppc64,     6-ppc64le,
  7-mips,      8-mipsle,    9-mips64,
  10-mips64le, 11-s390x`)
	signhash := cmd.Flags().Int32("signhash", 0, `the signature hash used (with -datatype 5-Signature)
[NEEDED, no default]:
  1-SHA256,    2-SHA384,    3-SHA512,
  4-BLAKE2S,   5-BLAKE2B`)
	signentity := cmd.Flags().String("signentity", "", `the entity that signs (with -datatype 5-Signature)
[NEEDED, no default]:
  example: 433FE984155206BD962725E20E8713472A879943`)
	groupid := cmd.Flags().Uint32("groupid", 0, "set groupid [default: 0]")
	link := cmd.Flags().Uint32("link", 0, "set link pointer [default: 0]")
	alignment := cmd.Flags().Int("alignment", 0, "set alignment constraint [default: aligned on page size]")
	filename := cmd.Flags().String("filename", "", "set logical filename/handle [default: input filename]")

	cmd.PreRunE = c.initApp
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		opts := siftool.AddOptions{
			Groupid:   *groupid,
			Link:      *link,
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

		return c.app.Add(args[0], opts)
	}

	return cmd
}
