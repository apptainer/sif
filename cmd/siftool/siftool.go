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
	del      delete a specified object descriptor and data from SIF file
`

const usageHeader = "" +
	`usage: header containerfile
`

const usageList = "" +
	`usage: list containerfile
`

const usageInfo = "" +
	`usage: info descriptorid containerfile
`

const usageDump = "" +
	`usage: dump descriptorid containerfile
`

const usageDel = "" +
	`usage: del descriptorid containerfile
`

func usage() {
	fmt.Fprintln(os.Stderr, usageMessage)
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	log.SetFlags(0)

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
	}

	switch args[0] {
	case "header":
		err := cmdHeader(args[1:])
		if err != nil {
			if err.Error() == "usage" {
				log.Fatal(usageHeader)
			} else {
				log.Fatal("error running `header' command:", err)
			}
		}
	case "list":
		err := cmdList(args[1:])
		if err != nil {
			if err.Error() == "usage" {
				log.Fatal(usageList)
			} else {
				log.Fatal("error running `list' command:", err)
			}
		}
	case "info":
		err := cmdInfo(args[1:])
		if err != nil {
			if err.Error() == "usage" {
				log.Fatal(usageInfo)
			} else {
				log.Fatal("error running `info' command:", err)
			}
		}
	case "dump":
		err := cmdDump(args[1:])
		if err != nil {
			if err.Error() == "usage" {
				log.Fatal(usageDump)
			} else {
				log.Fatal("error running `dump' command:", err)
			}
		}
	case "del":
		err := cmdDel(args[1:])
		if err != nil {
			if err.Error() == "usage" {
				log.Fatal(usageDel)
			} else {
				log.Fatal("error running `del' command:", err)
			}
		}
	default:
		log.Fatal("Unknown command:", args[0])
	}
}
