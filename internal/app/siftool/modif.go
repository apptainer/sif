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
	"io"

	"github.com/apptainer/sif/v2/pkg/sif"
)

// New creates a new empty SIF file.
func (*App) New(path string) error {
	f, err := sif.CreateContainerAtPath(path)
	if err != nil {
		return err
	}

	return f.UnloadContainer()
}

// Add adds a data object to a SIF file.
func (*App) Add(path string, t sif.DataType, r io.Reader, opts ...sif.DescriptorInputOpt) error {
	return withFileImage(path, true, func(f *sif.FileImage) error {
		input, err := sif.NewDescriptorInput(t, r, opts...)
		if err != nil {
			return err
		}

		return f.AddObject(input)
	})
}

// Del deletes a specified object descriptor and data from the SIF file.
func (*App) Del(path string, id uint32) error {
	return withFileImage(path, true, func(f *sif.FileImage) error {
		return f.DeleteObject(id)
	})
}

// Setprim sets the primary system partition of the SIF file.
func (*App) Setprim(path string, id uint32) error {
	return withFileImage(path, true, func(f *sif.FileImage) error {
		return f.SetPrimPart(id)
	})
}
