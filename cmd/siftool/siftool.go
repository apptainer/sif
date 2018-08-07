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
	"log"
	"os"
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
`

func usage() {
	fmt.Fprintln(os.Stderr, usageMessage)
	os.Exit(2)
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
	-datatype     the type of data to add (NEEDED no default):
	                1-Deffile,   2-EnvVar,    3-Labels,
	                4-Partition, 5-Signature, 6-GenericJSON
	-parttype     the type of parition used when using -datatype 3-Partition
	                1-System,    2-Data,      3-Overlay
	-partfs       the filesystem in used inside partition (3-Partition)
	                1-Squash,    2-Ext3,      3-ImmuObj,
	                4-Raw
	-signhash     the signature hash in use when using -datatype 4-Signature
	                1-SHA256,    2-SHA384,    3-SHA512,
	                4-BLAKE2S,   5-BLAKE2B
	-signentity   the entity signing data when using -datatype 4-Signature
	                finger: (e.g., 433FE984155206BD962725E20E8713472A879943)
	-groupid      set groupid (default: DescrUnusedGroup)
	-link         set link pointer (default: DescrUnusedLink)
	-alignment    set alignment constraint (default: aligned on page size)
	-filename     set logical filename/handle (default: input filename)
`},
		"del": {"del", cmdDel, "" +
			`usage: del descriptorid containerfile
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
