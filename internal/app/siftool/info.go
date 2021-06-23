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
	"os"
	"time"

	"github.com/hpcng/sif/v2/pkg/sif"
)

// Header displays a SIF file global header.
func (*App) Header(path string) error {
	return withFileImage(path, true, func(f *sif.FileImage) error {
		//nolint:staticcheck // In use until v2 API to avoid code duplication
		_, err := fmt.Print(f.FmtHeader())
		return err
	})
}

// List displays a list of all active descriptors from a SIF file.
func (*App) List(path string) error {
	return withFileImage(path, false, func(f *sif.FileImage) error {
		fmt.Println("Container id:", f.Header.ID)
		fmt.Println("Created on:  ", time.Unix(f.Header.Ctime, 0).UTC())
		fmt.Println("Modified on: ", time.Unix(f.Header.Mtime, 0).UTC())
		fmt.Println("----------------------------------------------------")

		fmt.Println("Descriptor list:")

		//nolint:staticcheck // In use until v2 API to avoid code duplication
		_, err := fmt.Print(f.FmtDescrList())
		return err
	})
}

// Info displays detailed info about a descriptor from a SIF file.
func (*App) Info(path string, id uint32) error {
	return withFileImage(path, false, func(f *sif.FileImage) error {
		//nolint:staticcheck // In use until v2 API to avoid code duplication
		_, err := fmt.Print(f.FmtDescrInfo(id))
		return err
	})
}

// Dump extracts and outputs a data object from a SIF file.
func (*App) Dump(path string, id uint32) error {
	return withFileImage(path, false, func(f *sif.FileImage) error {
		d, _, err := f.GetFromDescrID(id)
		if err != nil {
			return err
		}

		_, err = io.CopyN(os.Stdout, d.GetReader(f), d.Filelen)
		return err
	})
}
