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
	"math"
	"strings"
	"text/tabwriter"

	"github.com/hpcng/sif/v2/pkg/sif"
)

// readableSize returns the size in human readable format.
func readableSize(size uint64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}

	units := "KMGTPE"

	div, exp := uint64(1024), 0
	for n := size / 1024; (n >= 1024) && (exp < len(units)-1); n /= 1024 {
		div *= 1024
		exp++
	}

	return fmt.Sprintf("%.0f %ciB", math.Round(float64(size)/float64(div)), units[exp])
}

// writeHeader writes header information in f to w.
func writeHeader(w io.Writer, f *sif.FileImage) error {
	tw := tabwriter.NewWriter(w, 0, 0, 0, ' ', 0)

	fmt.Fprintln(tw, "Launch:\t", strings.TrimSuffix(f.LaunchScript(), "\n"))
	fmt.Fprintln(tw, "Version:\t", f.Version())
	fmt.Fprintln(tw, "Arch:\t", f.PrimaryArch())
	fmt.Fprintln(tw, "ID:\t", f.ID())
	fmt.Fprintln(tw, "Ctime:\t", f.CreatedAt())
	fmt.Fprintln(tw, "Mtime:\t", f.ModifiedAt())
	fmt.Fprintln(tw, "Dfree:\t", f.DescriptorsFree())
	fmt.Fprintln(tw, "Dtotal:\t", f.DescriptorsTotal())
	fmt.Fprintln(tw, "Descoff:\t", f.DescriptorSectionOffset())
	fmt.Fprintln(tw, "Descrlen:\t", readableSize(f.DescriptorSectionSize()))
	fmt.Fprintln(tw, "Dataoff:\t", f.DataSectionOffset())
	fmt.Fprintln(tw, "Datalen:\t", readableSize(f.DataSectionSize()))

	return tw.Flush()
}

// Header displays a SIF file global header.
func (a *App) Header(path string) error {
	return withFileImage(path, false, func(f *sif.FileImage) error {
		return writeHeader(a.opts.out, f)
	})
}

// List displays a list of all active descriptors from a SIF file.
func (a *App) List(path string) error {
	return withFileImage(path, false, func(f *sif.FileImage) error {
		fmt.Fprintln(a.opts.out, "Container id:", f.ID())
		fmt.Fprintln(a.opts.out, "Created on:  ", f.CreatedAt())
		fmt.Fprintln(a.opts.out, "Modified on: ", f.ModifiedAt())
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
		d, err := f.GetDescriptor(sif.WithID(id))
		if err != nil {
			return err
		}

		_, err = io.CopyN(a.opts.out, d.GetReader(f), d.GetSize())
		return err
	})
}
