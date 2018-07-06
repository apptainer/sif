// Copyright (c) 2018, Divya Cote <divya.cote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"fmt"
	"github.com/sylabs/sif/pkg/sif"
	"time"
)

// readableSize returns the size in human readable format
func readableSize(size uint64) string {
	var divs int
	var conversion string

	for ; size != 0; size >>= 10 {
		if size < 1024 {
			break
		}
		divs++
	}

	switch divs {
	case 0:
		conversion = fmt.Sprintf("%d", size)
	case 1:
		conversion = fmt.Sprintf("%dKB", size)
	case 2:
		conversion = fmt.Sprintf("%dMB", size)
	case 3:
		conversion = fmt.Sprintf("%dGB", size)
	case 4:
		conversion = fmt.Sprintf("%dTB", size)
	}
	return conversion
}

// archStr returns a human readable version of SIF mach architecture
func archStr(arch string) string {
	archMap := map[string]string{
		sif.HdrArch386:      "386",
		sif.HdrArchAMD64:    "amd64",
		sif.HdrArchARM:      "arm",
		sif.HdrArchARM64:    "arm64",
		sif.HdrArchPPC64:    "ppc64",
		sif.HdrArchPPC64le:  "ppc64le",
		sif.HdrArchMIPS:     "mips",
		sif.HdrArchMIPSle:   "mipsle",
		sif.HdrArchMIPS64:   "mips64",
		sif.HdrArchMIPS64le: "mips64le",
		sif.HdrArchS390x:    "s390x",
	}
	if archMap[arch[:2]] == "" {
		return "unknown arch"
	}
	return archMap[arch[:2]]
}

// cmdHeader displays a SIF file global header to stdout
func cmdHeader(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage")
	}

	fimg, err := sif.LoadContainer(args[0], true)
	if err != nil {
		return fmt.Errorf("while loading SIF file: %s", err)
	}
	defer fimg.UnloadContainer()

	fmt.Println("Launch:  ", string(fimg.Header.Launch[:]))
	fmt.Println("Magic:   ", string(fimg.Header.Magic[:]))
	fmt.Println("Version: ", string(fimg.Header.Version[:]))
	fmt.Println("Arch:    ", archStr(string(fimg.Header.Arch[:])))
	fmt.Println("ID:      ", fimg.Header.ID)
	fmt.Println("Ctime:   ", time.Unix(fimg.Header.Ctime, 0))
	fmt.Println("Mtime:   ", time.Unix(fimg.Header.Mtime, 0))
	fmt.Println("Dfree:   ", fimg.Header.Dfree)
	fmt.Println("Dtotal:  ", fimg.Header.Dtotal)
	fmt.Println("Descoff: ", fimg.Header.Descroff)
	fmt.Println("Descrlen:", readableSize(uint64(fimg.Header.Descrlen)))
	fmt.Println("Dataoff: ", fimg.Header.Dataoff)
	fmt.Println("Datalen: ", readableSize(uint64(fimg.Header.Datalen)))

	return nil
}

// cmdList displays a list of all active descriptors from a SIF file to stdout
func cmdList(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage")
	}

	fimg, err := sif.LoadContainer(args[0], true)
	if err != nil {
		return fmt.Errorf("while loading SIF file: %s", err)
	}
	defer fimg.UnloadContainer()

	return nil
}

// cmdInfo displays detailed info about a descriptor from a SIF file to stdout
func cmdInfo(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	fimg, err := sif.LoadContainer(args[0], true)
	if err != nil {
		return fmt.Errorf("while loading SIF file: %s", err)
	}
	defer fimg.UnloadContainer()

	return nil
}

// cmdDump extracts and output a data object from a SIF file to stdout
func cmdDump(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	fimg, err := sif.LoadContainer(args[0], true)
	if err != nil {
		return fmt.Errorf("while loading SIF file: %s", err)
	}
	defer fimg.UnloadContainer()

	return nil
}
