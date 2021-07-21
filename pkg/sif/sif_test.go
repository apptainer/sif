// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.
package sif

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/sebdah/goldie/v2"
)

func TestHeader_GetIntegrityReader(t *testing.T) {
	h := header{
		Arch:  hdrArchAMD64,
		ID:    uuid.UUID{0xb2, 0x65, 0x9d, 0x4e, 0xbd, 0x50, 0x4e, 0xa5, 0xbd, 0x17, 0xee, 0xc5, 0xe5, 0x4f, 0x91, 0x8e},
		Ctime: 1504657553,
		Mtime: 1504657653,
	}
	copy(h.Launch[:], hdrLaunch)
	copy(h.Magic[:], hdrMagic)
	copy(h.Version[:], CurrentVersion.bytes())

	tests := []struct {
		name    string
		modFunc func(h header) header
	}{
		{"Launch", func(h header) header {
			copy(h.Launch[:], "#!/usr/bin/env rm\n")
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
		{"Ctime", func(h header) header {
			h.Ctime++
			return h
		}},
		{"Mtime", func(h header) header {
			h.Mtime++
			return h
		}},
		{"Dfree", func(h header) header {
			h.Dfree++
			return h
		}},
		{"Dtotal", func(h header) header {
			h.Dtotal++
			return h
		}},
		{"Descroff", func(h header) header {
			h.Descroff++
			return h
		}},
		{"Descrlen", func(h header) header {
			h.Descrlen++
			return h
		}},
		{"Dataoff", func(h header) header {
			h.Dataoff++
			return h
		}},
		{"Datalen", func(h header) header {
			h.Datalen++
			return h
		}},
	}

	for _, tt := range tests {
		tt := tt
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
