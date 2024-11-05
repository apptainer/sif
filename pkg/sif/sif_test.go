// Copyright (c) Contributors to the Apptainer project, established as
//
//	Apptainer a Series of LF Projects LLC.
//	For website terms of use, trademark policy, privacy policy and other
//	project policies see https://lfprojects.org/policies
//
// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.
package sif

import (
	"bytes"
	"io"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/sebdah/goldie/v2"
)

var corpus = filepath.Join("..", "..", "test", "images")

func TestHeader_GetIntegrityReader(t *testing.T) {
	h := header{
		Magic:      hdrMagic,
		Version:    CurrentVersion.bytes(),
		Arch:       hdrArchAMD64,
		ID:         uuid.UUID{0xb2, 0x65, 0x9d, 0x4e, 0xbd, 0x50, 0x4e, 0xa5, 0xbd, 0x17, 0xee, 0xc5, 0xe5, 0x4f, 0x91, 0x8e},
		CreatedAt:  1504657553,
		ModifiedAt: 1504657653,
	}
	copy(h.LaunchScript[:], "#!/usr/bin/env run-singularity\n")

	tests := []struct {
		name    string
		modFunc func(h header) header
	}{
		{"LaunchScript", func(h header) header {
			copy(h.LaunchScript[:], "#!/usr/bin/env rm\n")
			return h
		}},
		{"Magic", func(h header) header {
			copy(h.Magic[:], "BAD_MAGIC")
			return h
		}},
		{"Version", func(h header) header {
			copy(h.Version[:], "02")
			return h
		}},
		{"Arch", func(h header) header {
			h.Arch = hdrArchS390x
			return h
		}},
		{"ID", func(h header) header {
			h.ID[0]++
			return h
		}},
		{"CreatedAt", func(h header) header {
			h.CreatedAt++
			return h
		}},
		{"ModifiedAt", func(h header) header {
			h.ModifiedAt++
			return h
		}},
		{"DescriptorsFree", func(h header) header {
			h.DescriptorsFree++
			return h
		}},
		{"DescriptorsTotal", func(h header) header {
			h.DescriptorsTotal++
			return h
		}},
		{"DescriptorsOffset", func(h header) header {
			h.DescriptorsOffset++
			return h
		}},
		{"DescriptorsSize", func(h header) header {
			h.DescriptorsSize++
			return h
		}},
		{"DataOffset", func(h header) header {
			h.DataOffset++
			return h
		}},
		{"DataSize", func(h header) header {
			h.DataSize++
			return h
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}

			h := tt.modFunc(h)

			if _, err := io.Copy(&b, h.GetIntegrityReader()); err != nil {
				t.Fatal(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}
