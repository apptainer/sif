// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"testing"
)

func TestFileImage_WithDescriptors(t *testing.T) {
	ds := []Descriptor{
		{
			Datatype: DataPartition,
			Used:     true,
			ID:       1,
			Groupid:  1 | DescrGroupMask,
			Link:     DescrUnusedLink,
		},
		{
			Datatype: DataSignature,
			Used:     true,
			ID:       2,
			Groupid:  DescrUnusedGroup,
			Link:     1 | DescrGroupMask,
		},
		{
			Datatype: DataSignature,
			Used:     false,
			ID:       3,
			Groupid:  DescrUnusedGroup,
			Link:     DescrUnusedLink,
		},
	}

	tests := []struct {
		name string
		fn   func(t *testing.T) func(d Descriptor) bool
	}{
		{
			name: "ReturnTrue",
			fn: func(t *testing.T) func(d Descriptor) bool {
				return func(d Descriptor) bool {
					if id := d.GetID(); id > 1 {
						t.Errorf("unexpected ID: %v", id)
					}
					return true
				}
			},
		},
		{
			name: "ReturnFalse",
			fn: func(t *testing.T) func(d Descriptor) bool {
				return func(d Descriptor) bool {
					if id := d.GetID(); id > 2 {
						t.Errorf("unexpected ID: %v", id)
					}
					return false
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &FileImage{descrArr: ds}

			f.WithDescriptors(tt.fn(t))
		})
	}
}
