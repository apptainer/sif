// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"flag"
	"fmt"
	"github.com/sylabs/sif/pkg/sif"
	"log"
	"os"
	"runtime"
)

var usageMessage = `siftool is a utility program for manipulating SIF files.

Usage:

	siftool command [arguments]

The commands are:

	header   display SIF global headers
	list     list object descriptors from SIF files
	info     display detailed information of object descriptors
	dump     extract and output (stdout) data objects from SIF files
	new      create a new empty SIF image file
	add      add a data object to a SIF file
	del      delete a specified object descriptor and data from SIF file
	version  package version
	help     this help
`

func usage() {
	fmt.Fprintln(os.Stderr, usageMessage)
	os.Exit(2)
}

func cmdHelp(args []string) error {
	usage()
	return nil
}

var version = "unknown"

func cmdVersion(args []string) error {
	fmt.Printf("siftool version %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("SIF spec versions supported: <= %s\n", sif.HdrVersion)
	return nil
}

type action func([]string) error

type subcmd struct {
	name  string
	fn    action
	usage string
}

func main() {
	subcmds := map[string]subcmd{
		"header": {"header", cmdHeader, "" +
			`usage: header containerfile
`},
		"list": {"list", cmdList, "" +
			`usage: list containerfile
`},
		"info": {"info", cmdInfo, "" +
			`usage: info descriptorid containerfile
`},
		"dump": {"dump", cmdDump, "" +
			`usage: dump descriptorid containerfile
`},
		"new": {"new", cmdNew, "" +
			`usage: new containerfile
`},
		"add": {"add", cmdAdd, "" +
			`usage: add containerfile dataobjectfile|-
	-datatype     the type of data to add
	              [NEEDED, no default]:
	                1-Deffile,   2-EnvVar,    3-Labels,
	                4-Partition, 5-Signature, 6-GenericJSON
	-parttype     the type of parition (with -datatype 3-Partition)
	              [NEEDED, no default]:
	                1-System,    2-PrimSys,   3-Data,
	                4-Overlay
	-partfs       the filesystem in used (with -datatype 3-Partition)
	              [NEEDED, no default]:
	                1-Squash,    2-Ext3,      3-ImmuObj,
	                4-Raw
	-partarch     the main architecture used (with -datatype 3-Partition)
	              [NEEDED, no default]:
	                1-386,       2-amd64,     3-arm,
	                4-arm64,     5-ppc64,     6-ppc64le,
	                7-mips,      8-mipsle,    9-mips64,
	                10-mips64le, 11-s390x
	-signhash     the signature hash used (with -datatype 4-Signature)
	              [NEEDED, no default]:
	                1-SHA256,    2-SHA384,    3-SHA512,
	                4-BLAKE2S,   5-BLAKE2B
	-signentity   the entity that signs (with -datatype 4-Signature)
	              [NEEDED, no default]:
	                example: 433FE984155206BD962725E20E8713472A879943
	-groupid      set groupid [default: DescrUnusedGroup]
	-link         set link pointer [default: DescrUnusedLink]
	-alignment    set alignment constraint [default: aligned on page size]
	-filename     set logical filename/handle [default: input filename]
`},
		"del": {"del", cmdDel, "" +
			`usage: del descriptorid containerfile
`},
		"help": {"help", cmdHelp, "" +
			`usage: help
`},
		"version": {"version", cmdVersion, "" +
			`usage: version
`},
	}

	log.SetFlags(0)

	flag.Usage = usage
	if len(os.Args) < 2 {
		flag.Usage()
	}

	os.Args = os.Args[1:]
	subcommand := os.Args[0]

	flag.Parse()
	args := flag.Args()

	cmd, ok := subcmds[subcommand]
	if !ok {
		log.Fatal("Unknown command:", subcommand)
	}

	if err := cmd.fn(args); err != nil {
		if err.Error() == "usage" {
			log.Fatal(cmd.usage)
		} else {
			log.Fatalf("error running %s command: %s\n", cmd.name, err)
		}
	}
}
