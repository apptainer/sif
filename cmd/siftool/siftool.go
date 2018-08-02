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
	flag.PrintDefaults()
	os.Exit(2)
}

type action func([]string) error

type subcmd struct {
	name  string
	fn    action
	usage string
}

func main() {
	flag.Usage = usage
	flag.Parse()

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
			`usage: add dataobjectfile containerfile
`},
		"del": {"del", cmdDel, "" +
			`usage: del descriptorid containerfile
`},
	}

	log.SetFlags(0)

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
	}

	cmd, ok := subcmds[args[0]]
	if !ok {
		log.Fatal("Unknown command:", args[0])
	}

	if err := cmd.fn(args[1:]); err != nil {
		if err.Error() == "usage" {
			log.Fatal(cmd.usage)
		} else {
			log.Fatalf("error running %s command :%s\n", cmd.name, err)
		}
	}
}
