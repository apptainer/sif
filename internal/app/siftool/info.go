// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2018, Divya Cote <divya.cote@gmail.com> All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/hpcng/sif/pkg/sif"
)

// Header displays a SIF file global header.
func Header(path string) error {
	fimg, err := sif.LoadContainer(path, true)
	if err != nil {
		return err
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			log.Printf("Error unloading container: %v", err)
		}
	}()

	//nolint:staticcheck // In use until v2 API to avoid code duplication
	_, err = fmt.Print(fimg.FmtHeader())
	return err
}

// List displays a list of all active descriptors from a SIF file.
func List(path string) error {
	fimg, err := sif.LoadContainer(path, true)
	if err != nil {
		return err
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			log.Printf("Error unloading container: %v", err)
		}
	}()

	fmt.Println("Container id:", fimg.Header.ID)
	fmt.Println("Created on:  ", time.Unix(fimg.Header.Ctime, 0).UTC())
	fmt.Println("Modified on: ", time.Unix(fimg.Header.Mtime, 0).UTC())
	fmt.Println("----------------------------------------------------")

	fmt.Println("Descriptor list:")

	//nolint:staticcheck // In use until v2 API to avoid code duplication
	_, err = fmt.Print(fimg.FmtDescrList())
	return err
}

// Info displays detailed info about a descriptor from a SIF file.
func Info(path string, id uint32) error {
	fimg, err := sif.LoadContainer(path, true)
	if err != nil {
		return err
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			log.Printf("Error unloading container: %v", err)
		}
	}()

	//nolint:staticcheck // In use until v2 API to avoid code duplication
	_, err = fmt.Print(fimg.FmtDescrInfo(id))
	return err
}

// Dump extracts and outputs a data object from a SIF file.
func Dump(path string, id uint32) error {
	fimg, err := sif.LoadContainer(path, true)
	if err != nil {
		return err
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			log.Printf("Error unloading container: %v", err)
		}
	}()

	d, _, err := fimg.GetFromDescrID(id)
	if err != nil {
		return err
	}

	_, err = io.CopyN(os.Stdout, d.GetReader(&fimg), d.Filelen)
	return err
}
