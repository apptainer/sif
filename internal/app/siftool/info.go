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
	"github.com/google/uuid"
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
	tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', 0)

	if s := f.LaunchScript(); s != "" {
		fmt.Fprintf(tw, "Launch Script:\t%v\n", strings.TrimSuffix(s, "\n"))
	}

	fmt.Fprintf(tw, "Version:\t%v\n", f.Version())

	if arch := f.PrimaryArch(); arch != "unknown" {
		fmt.Fprintf(tw, "Primary Architecture:\t%v\n", arch)
	}

	if id := f.ID(); id != uuid.Nil.String() {
		fmt.Fprintf(tw, "ID:\t%v\n", id)
	}

	if t := f.CreatedAt(); !t.IsZero() {
		fmt.Fprintf(tw, "Created At:\t%v\n", t.UTC())
	}

	if t := f.ModifiedAt(); !t.IsZero() {
		fmt.Fprintf(tw, "Modified At:\t%v\n", t.UTC())
	}

	fmt.Fprintf(tw, "Descriptors Free:\t%v\n", f.DescriptorsFree())
	fmt.Fprintf(tw, "Descriptors Total:\t%v\n", f.DescriptorsTotal())
	fmt.Fprintf(tw, "Descriptors Offset:\t%v\n", f.DescriptorsOffset())
	fmt.Fprintf(tw, "Descriptors Size:\t%v\n", readableSize(f.DescriptorsSize()))
	fmt.Fprintf(tw, "Data Offset:\t%v\n", f.DataOffset())
	fmt.Fprintf(tw, "Data Size:\t%v\n", readableSize(f.DataSize()))

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
	fmt.Fprintln(w, ("------------------------------------------------------------------------------"))
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
			fs, pt, arch, err := d.PartitionMetadata()
			if err == nil {
				fmt.Fprintf(w, "|%s (%s/%s/%s)\n", dt, fs, pt, arch)
			}
		case sif.DataSignature:
			ht, _, err := d.SignatureMetadata()
			if err == nil {
				fmt.Fprintf(w, "|%s (%s)\n", dt, ht)
			}
		case sif.DataCryptoMessage:
			ft, mt, err := d.CryptoMessageMetadata()
			if err == nil {
				fmt.Fprintf(w, "|%s (%s/%s)\n", dt, ft, mt)
			}
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
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintf(tw, "\tData Type:\t%v\n", v.DataType())
	fmt.Fprintf(tw, "\tID:\t%v\n", v.ID())

	fmt.Fprint(tw, "\tGroup ID:\t")
	if id := v.GroupID(); id == 0 {
		fmt.Fprintln(tw, "NONE")
	} else {
		fmt.Fprintln(tw, id)
	}

	fmt.Fprint(tw, "\tLinked ID:\t")
	switch id, isGroup := v.LinkedID(); {
	case id == 0:
		fmt.Fprintln(tw, "NONE")
	case isGroup:
		fmt.Fprintln(tw, id, "(G)")
	default:
		fmt.Fprintln(tw, id)
	}

	fmt.Fprintf(tw, "\tOffset:\t%v\n", v.Offset())
	fmt.Fprintf(tw, "\tSize:\t%v\n", v.Size())

	if t := v.CreatedAt(); !t.IsZero() {
		fmt.Fprintf(tw, "\tCreated At:\t%v\n", t.UTC())
	}

	if t := v.ModifiedAt(); !t.IsZero() {
		fmt.Fprintf(tw, "\tModified At:\t%v\n", t.UTC())
	}

	if nm := v.Name(); nm != "" {
		fmt.Fprintf(tw, "\tName:\t%v\n", nm)
	}

	switch v.DataType() {
	case sif.DataPartition:
		fs, pt, arch, err := v.PartitionMetadata()
		if err != nil {
			return err
		}

		fmt.Fprintf(tw, "\tFilesystem Type:\t%v\n", fs)
		fmt.Fprintf(tw, "\tPartition Type:\t%v\n", pt)
		fmt.Fprintf(tw, "\tArchitecture:\t%v\n", arch)

	case sif.DataSignature:
		ht, fp, err := v.SignatureMetadata()
		if err != nil {
			return err
		}

		fmt.Fprintf(tw, "\tHash Type:\t%v\n", ht)
		fmt.Fprintf(tw, "\tEntity:\t%X\n", fp)

	case sif.DataCryptoMessage:
		ft, mt, err := v.CryptoMessageMetadata()
		if err != nil {
			return err
		}

		fmt.Fprintf(tw, "\tFormat Type:\t%v\n", ft)
		fmt.Fprintf(tw, "\tMessage Type:\t%v\n", mt)
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
