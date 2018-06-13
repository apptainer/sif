// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import ()

// GetHeader returns the loaded SIF global header
func (fimg *FileImage) GetHeader() *Header {
	return &fimg.header
}

// GetFromDescrID search for a descriptor with
func (fimg *FileImage) GetFromDescrID(ID string) *Descriptor {
	for i, v := range fimg.descrArr {
		if v.Used == false {
			continue
		}
		return &fimg.descrArr[i]
	}

	return nil
}
