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

	"github.com/hpcng/sif/v2/pkg/sif"
	uuid "github.com/satori/go.uuid"
)

// New creates a new empty SIF file.
func New(path string) error {
	id, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("id generation failed: %v", err)
	}

	cinfo := sif.CreateInfo{
		Pathname:   path,
		Launchstr:  sif.HdrLaunch,
		Sifversion: sif.HdrVersion,
		ID:         id,
	}

	_, err = sif.CreateContainer(cinfo)
	return err
}

// AddOptions contains the options when adding a section to a SIF file.
type AddOptions struct {
	Datatype   sif.Datatype
	Parttype   sif.Parttype
	Partfs     sif.Fstype
	Partarch   string
	Signhash   sif.Hashtype
	Signentity string
	Groupid    uint32
	Link       uint32
	Alignment  int
	Filename   string
	Fp         io.Reader
}

// Add adds a data object to a SIF file.
func Add(path string, opts AddOptions) error {
	input := sif.DescriptorInput{
		Datatype:  opts.Datatype,
		Groupid:   sif.DescrGroupMask | opts.Groupid,
		Link:      opts.Link,
		Alignment: opts.Alignment,
		Fname:     opts.Filename,
		Fp:        opts.Fp,
	}

	if opts.Datatype == sif.DataPartition {
		if err := input.SetPartExtra(opts.Partfs, opts.Parttype, opts.Partarch); err != nil {
			return err
		}
	} else if opts.Datatype == sif.DataSignature {
		if err := input.SetSignExtra(opts.Signhash, opts.Signentity); err != nil {
			return err
		}
	}

	return withFileImage(path, true, func(f *sif.FileImage) error {
		return f.AddObject(input)
	})
}

// Del deletes a specified object descriptor and data from the SIF file.
func Del(path string, id uint32) error {
	return withFileImage(path, true, func(f *sif.FileImage) error {
		return f.DeleteObject(id, 0)
	})
}

// Setprim sets the primary system partition of the SIF file.
func Setprim(path string, id uint32) error {
	return withFileImage(path, true, func(f *sif.FileImage) error {
		return f.SetPrimPart(id)
	})
}
