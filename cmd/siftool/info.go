// Copyright (c) 2018, Divya Cote <divya.cote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/sylabs/sif/pkg/sif"
)

// cmdHeader displays a SIF file global header to stdout
func cmdHeader(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage")
	}

	fimg, err := sif.LoadContainer(args[0], true)
	if err != nil {
		return err
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			fmt.Println("Error unloading container: ", err)
		}
	}()

	fmt.Print(fimg.FmtHeader())

	return nil
}

// cmdList displays a list of all active descriptors from a SIF file to stdout
func cmdList(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage")
	}

	fimg, err := sif.LoadContainer(args[0], true)
	if err != nil {
		return err
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			fmt.Println("Error unloading container: ", err)
		}
	}()

	fmt.Println("Container id:", fimg.Header.ID)
	fmt.Println("Created on:  ", time.Unix(fimg.Header.Ctime, 0))
	fmt.Println("Modified on: ", time.Unix(fimg.Header.Mtime, 0))
	fmt.Println("----------------------------------------------------")

	fmt.Println("Descriptor list:")

	fmt.Print(fimg.FmtDescrList())

	return nil
}

// cmdInfo displays detailed info about a descriptor from a SIF file to stdout
func cmdInfo(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("while converting input descriptor id: %s", err)
	}

	fimg, err := sif.LoadContainer(args[1], true)
	if err != nil {
		return err
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			fmt.Println("Error unloading container: ", err)
		}
	}()

	fmt.Print(fimg.FmtDescrInfo(uint32(id)))

	return nil
}

// cmdDump extracts and output a data object from a SIF file to stdout
func cmdDump(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("while converting input descriptor id: %s", err)
	}

	fimg, err := sif.LoadContainer(args[1], true)
	if err != nil {
		return err
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			fmt.Println("Error unloading container: ", err)
		}
	}()

	for _, v := range fimg.DescrArr {
		if !v.Used {
			continue
		} else if v.ID == uint32(id) {
			if _, err := fimg.Fp.Seek(v.Fileoff, 0); err != nil {
				return fmt.Errorf("while seeking to data object: %s", err)
			}
			if _, err := io.CopyN(os.Stdout, fimg.Fp, v.Filelen); err != nil {
				return fmt.Errorf("while copying data object to stdout: %s", err)
			}

			return nil
		}
	}

	return fmt.Errorf("descriptor not in range or currently unused")
}
