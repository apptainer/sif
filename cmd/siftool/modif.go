// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"flag"
	"fmt"
	"strconv"

	"github.com/hpcng/sif/internal/app/siftool"
	"github.com/hpcng/sif/pkg/sif"
)

var (
	datatype   = flag.Int64("datatype", -1, "")
	parttype   = flag.Int64("parttype", -1, "")
	partfs     = flag.Int64("partfs", -1, "")
	partarch   = flag.Int64("partarch", -1, "")
	signhash   = flag.Int64("signhash", -1, "")
	signentity = flag.String("signentity", "", "")
	groupid    = flag.Int64("groupid", sif.DescrUnusedGroup, "")
	link       = flag.Int64("link", sif.DescrUnusedLink, "")
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
		Datatype:   datatype,
		Parttype:   parttype,
		Partfs:     partfs,
		Partarch:   partarch,
		Signhash:   signhash,
		Signentity: signentity,
		Groupid:    groupid,
		Link:       link,
		Alignment:  alignment,
		Filename:   filename,
	}

	return siftool.Add(args[0], args[1], opts)
}

func cmdDel(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("while converting input descriptor id: %s", err)
	}

	return siftool.Del(id, args[1])
}

func cmdSetPrim(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("while converting input descriptor id: %s", err)
	}

	return siftool.Setprim(id, args[0])
}
