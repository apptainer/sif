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

	fmt.Fprintln(tw, "Launch:\t", strings.TrimSuffix(f.LaunchScript(), "\n"))
	fmt.Fprintln(tw, "Version:\t", f.Version())
	fmt.Fprintln(tw, "Arch:\t", f.PrimaryArch())
	fmt.Fprintln(tw, "ID:\t", f.ID())
	fmt.Fprintln(tw, "Ctime:\t", f.CreatedAt())
	fmt.Fprintln(tw, "Mtime:\t", f.ModifiedAt())
	fmt.Fprintln(tw, "Dfree:\t", f.DescriptorsFree())
	fmt.Fprintln(tw, "Dtotal:\t", f.DescriptorsTotal())
	fmt.Fprintln(tw, "Descoff:\t", f.DescriptorsOffset())
	fmt.Fprintln(tw, "Descrlen:\t", readableSize(f.DescriptorsSize()))
	fmt.Fprintln(tw, "Dataoff:\t", f.DataOffset())
	fmt.Fprintln(tw, "Datalen:\t", readableSize(f.DataSize()))

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
	fmt.Fprintln(w, "Container id:", f.ID())
	fmt.Fprintln(w, "Created on:  ", f.CreatedAt())
	fmt.Fprintln(w, "Modified on: ", f.ModifiedAt())
	fmt.Fprintln(w, "----------------------------------------------------")

	fmt.Fprintln(w, "Descriptor list:")

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

	fmt.Fprintln(tw, "  Datatype:\t", v.DataType())
	fmt.Fprintln(tw, "  ID:\t", v.ID())

	if id := v.GroupID(); id == 0 {
		fmt.Fprintln(tw, "  Groupid:\t", "NONE")
	} else {
		fmt.Fprintln(tw, "  Groupid:\t", id)
	}

	switch id, isGroup := v.LinkedID(); {
	case id == 0:
		fmt.Fprintln(tw, "  Link:\t", "NONE")
	case isGroup:
		fmt.Fprintln(tw, "  Link:\t", id, "(G)")
	default:
		fmt.Fprintln(tw, "  Link:\t", id)
	}

	fmt.Fprintln(tw, "  Fileoff:\t", v.Offset())
	fmt.Fprintln(tw, "  Filelen:\t", v.Size())
	fmt.Fprintln(tw, "  Ctime:\t", v.CreatedAt())
	fmt.Fprintln(tw, "  Mtime:\t", v.ModifiedAt())
	fmt.Fprintln(tw, "  Name:\t", v.Name())
	switch v.DataType() {
	case sif.DataPartition:
		fs, pt, arch, _ := v.PartitionMetadata()
		fmt.Fprintln(tw, "  Fstype:\t", fs)
		fmt.Fprintln(tw, "  Parttype:\t", pt)
		fmt.Fprintln(tw, "  Arch:\t", arch)
	case sif.DataSignature:
		ht, fp, _ := v.SignatureMetadata()
		fmt.Fprintln(tw, "  Hashtype:\t", ht)
		fmt.Fprintln(tw, "  Entity:\t", fmt.Sprintf("%X", fp))
	case sif.DataCryptoMessage:
		ft, mt, _ := v.CryptoMessageMetadata()
		fmt.Fprintln(tw, "  Fmttype:\t", ft)
		fmt.Fprintln(tw, "  Msgtype:\t", mt)
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
