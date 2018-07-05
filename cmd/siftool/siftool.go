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

const usageMessage = "" +
	`Usage of 'siftool':
`

func usage() {
	fmt.Fprintln(os.Stderr, usageMessage)
	fmt.Fprintln(os.Stderr, "Flags:")
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
			log.Fatal("error running `header' command:", err)
		}
	case "list":
		err := cmdList(args[1:])
		if err != nil {
			log.Fatal("error running `list' command:", err)
		}
	case "info":
		err := cmdInfo(args[1:])
		if err != nil {
			log.Fatal("error running `info' command:", err)
		}
	case "dump":
		err := cmdDump(args[1:])
		if err != nil {
			log.Fatal("error running `dump' command:", err)
		}
	case "del":
		err := cmdDel(args[1:])
		if err != nil {
			log.Fatal("error running `del' command:", err)
		}
	default:
		log.Fatal("Unknown command:", args[0])
	}
}
