// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
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

	"github.com/apptainer/sif/v2/pkg/sif"
)

// readableSize returns the size in human readable format.
func readableSize(size int64) string {
	if -1024 < size && size < 1024 {
		return fmt.Sprintf("%d B", size)
	}

	units := "KMGTPE"

	div, exp := uint64(1024), 0
	for n := size / 1024; (n <= -1024) || (1024 <= n); n /= 1024 {
		div *= 1024
		exp++
	}

	return fmt.Sprintf("%.0f %ciB", math.Round(float64(size)/float64(div)), units[exp])
}

// writeHeader writes header information in f to w.
func writeHeader(w io.Writer, f *sif.FileImage) error {
	tw := tabwriter.NewWriter(w, 0, 0, 0, ' ', 0)

	if s := f.LaunchScript(); s != "" {
		fmt.Fprintln(tw, "Launch Script:\t", strings.TrimSuffix(s, "\n"))
	}
	fmt.Fprintln(tw, "Version:\t", f.Version())
	fmt.Fprintln(tw, "Primary Architecture:\t", f.PrimaryArch())
	fmt.Fprintln(tw, "ID:\t", f.ID())
	fmt.Fprintln(tw, "Created At:\t", f.CreatedAt().UTC())
	fmt.Fprintln(tw, "Modified At:\t", f.ModifiedAt().UTC())
	fmt.Fprintln(tw, "Descriptors Free:\t", f.DescriptorsFree())
	fmt.Fprintln(tw, "Descriptors Total:\t", f.DescriptorsTotal())
	fmt.Fprintln(tw, "Descriptors Offset:\t", f.DescriptorsOffset())
	fmt.Fprintln(tw, "Descriptors Size:\t", readableSize(f.DescriptorsSize()))
	fmt.Fprintln(tw, "Data Offset:\t", f.DataOffset())
	fmt.Fprintln(tw, "Data Size:\t", readableSize(f.DataSize()))

	return tw.Flush()
}

// Header displays a SIF file global header.
func (a *App) Header(path string) error {
	return withFileImage(path, false, func(f *sif.FileImage) error {
		return writeHeader(a.opts.out, f)
	})
}

// writeList writes the list of descriptors in f to w.
func writeList(w io.Writer, f *sif.FileImage) error {
	fmt.Fprintln(w, "ID:          ", f.ID())
	fmt.Fprintln(w, "Created At:  ", f.CreatedAt().UTC())
	fmt.Fprintln(w, "Modified At: ", f.ModifiedAt().UTC())
	fmt.Fprintln(w, "----------------------------------------------------")

	fmt.Fprintln(w, "Descriptors:")

	fmt.Fprintf(w, "%-4s %-8s %-8s %-26s %s\n", "ID", "|GROUP", "|LINK", "|SIF POSITION (start-end)", "|TYPE")
	fmt.Fprintln(w, ("------------------------------------------------------------------------------"))

	f.WithDescriptors(func(d sif.Descriptor) bool {
		fmt.Fprintf(w, "%-4d ", d.ID())

		if id := d.GroupID(); id == 0 {
			fmt.Fprintf(w, "|%-7s ", "NONE")
		} else {
			fmt.Fprintf(w, "|%-7d ", id)
		}

		switch id, isGroup := d.LinkedID(); {
		case id == 0:
			fmt.Fprintf(w, "|%-7s ", "NONE")
		case isGroup:
			fmt.Fprintf(w, "|%-3d (G) ", id)
		default:
			fmt.Fprintf(w, "|%-7d ", id)
		}

		fmt.Fprintf(w, "%-26s ", fmt.Sprintf("|%d-%d ", d.Offset(), d.Offset()+d.Size()))

		switch dt := d.DataType(); dt {
		case sif.DataPartition:
			fs, pt, arch, _ := d.PartitionMetadata()
			fmt.Fprintf(w, "|%s (%s/%s/%s)\n", dt, fs, pt, arch)
		case sif.DataSignature:
			ht, _, _ := d.SignatureMetadata()
			fmt.Fprintf(w, "|%s (%s)\n", dt, ht)
		case sif.DataCryptoMessage:
			ft, mt, _ := d.CryptoMessageMetadata()
			fmt.Fprintf(w, "|%s (%s/%s)\n", dt, ft, mt)
		default:
			fmt.Fprintf(w, "|%s\n", dt)
		}

		return false
	})

	return nil
}

// List displays a list of all active descriptors from a SIF file.
func (a *App) List(path string) error {
	return withFileImage(path, false, func(f *sif.FileImage) error {
		return writeList(a.opts.out, f)
	})
}

// writeInfo writes info about d to w.
func writeInfo(w io.Writer, v sif.Descriptor) error {
	tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', 0)

	fmt.Fprintln(tw, "  Data Type:\t", v.DataType())
	fmt.Fprintln(tw, "  ID:\t", v.ID())

	if id := v.GroupID(); id == 0 {
		fmt.Fprintln(tw, "  Group ID:\t", "NONE")
	} else {
		fmt.Fprintln(tw, "  Group ID:\t", id)
	}

	switch id, isGroup := v.LinkedID(); {
	case id == 0:
		fmt.Fprintln(tw, "  Linked ID:\t", "NONE")
	case isGroup:
		fmt.Fprintln(tw, "  Linked ID:\t", id, "(G)")
	default:
		fmt.Fprintln(tw, "  Linked ID:\t", id)
	}

	fmt.Fprintln(tw, "  Offset:\t", v.Offset())
	fmt.Fprintln(tw, "  Size:\t", v.Size())
	fmt.Fprintln(tw, "  Created At:\t", v.CreatedAt().UTC())
	fmt.Fprintln(tw, "  Modified At:\t", v.ModifiedAt().UTC())
	fmt.Fprintln(tw, "  Name:\t", v.Name())
	switch v.DataType() {
	case sif.DataPartition:
		fs, pt, arch, _ := v.PartitionMetadata()
		fmt.Fprintln(tw, "  Filesystem Type:\t", fs)
		fmt.Fprintln(tw, "  Partition Type:\t", pt)
		fmt.Fprintln(tw, "  Architecture:\t", arch)
	case sif.DataSignature:
		ht, fp, _ := v.SignatureMetadata()
		fmt.Fprintln(tw, "  Hash Type:\t", ht)
		fmt.Fprintln(tw, "  Entity:\t", fmt.Sprintf("%X", fp))
	case sif.DataCryptoMessage:
		ft, mt, _ := v.CryptoMessageMetadata()
		fmt.Fprintln(tw, "  Format Type:\t", ft)
		fmt.Fprintln(tw, "  Message Type:\t", mt)
	}

	return tw.Flush()
}

// Info displays detailed info about a descriptor from a SIF file.
func (a *App) Info(path string, id uint32) error {
	return withFileImage(path, false, func(f *sif.FileImage) error {
		d, err := f.GetDescriptor(sif.WithID(id))
		if err != nil {
			return err
		}

		return writeInfo(a.opts.out, d)
	})
}

// Dump extracts and outputs a data object from a SIF file.
func (a *App) Dump(path string, id uint32) error {
	return withFileImage(path, false, func(f *sif.FileImage) error {
		d, err := f.GetDescriptor(sif.WithID(id))
		if err != nil {
			return err
		}

		_, err = io.CopyN(a.opts.out, d.GetReader(), d.Size())
		return err
	})
}
