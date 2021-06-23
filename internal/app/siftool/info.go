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
	"time"

	"github.com/hpcng/sif/v2/pkg/sif"
)

// Header displays a SIF file global header.
func (a *App) Header(path string) error {
	return withFileImage(path, true, func(f *sif.FileImage) error {
		//nolint:staticcheck // In use until v2 API to avoid code duplication
		_, err := fmt.Fprint(a.opts.out, f.FmtHeader())
		return err
	})
}

// List displays a list of all active descriptors from a SIF file.
func (a *App) List(path string) error {
	return withFileImage(path, false, func(f *sif.FileImage) error {
		fmt.Fprintln(a.opts.out, "Container id:", f.Header.ID)
		fmt.Fprintln(a.opts.out, "Created on:  ", time.Unix(f.Header.Ctime, 0).UTC())
		fmt.Fprintln(a.opts.out, "Modified on: ", time.Unix(f.Header.Mtime, 0).UTC())
		fmt.Fprintln(a.opts.out, "----------------------------------------------------")

		fmt.Fprintln(a.opts.out, "Descriptor list:")

		//nolint:staticcheck // In use until v2 API to avoid code duplication
		_, err := fmt.Fprint(a.opts.out, f.FmtDescrList())
		return err
	})
}

// Info displays detailed info about a descriptor from a SIF file.
func (a *App) Info(path string, id uint32) error {
	return withFileImage(path, false, func(f *sif.FileImage) error {
		//nolint:staticcheck // In use until v2 API to avoid code duplication
		_, err := fmt.Fprint(a.opts.out, f.FmtDescrInfo(id))
		return err
	})
}

// Dump extracts and outputs a data object from a SIF file.
func (a *App) Dump(path string, id uint32) error {
	return withFileImage(path, false, func(f *sif.FileImage) error {
		d, _, err := f.GetFromDescrID(id)
		if err != nil {
			return err
		}

		_, err = io.CopyN(a.opts.out, d.GetReader(f), d.Filelen)
		return err
	})
}
