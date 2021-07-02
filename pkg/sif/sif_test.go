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
	h := Header{
		ID:    uuid.UUID{0xb2, 0x65, 0x9d, 0x4e, 0xbd, 0x50, 0x4e, 0xa5, 0xbd, 0x17, 0xee, 0xc5, 0xe5, 0x4f, 0x91, 0x8e},
		Ctime: 1504657553,
		Mtime: 1504657653,
	}
	copy(h.Launch[:], HdrLaunch)
	copy(h.Magic[:], HdrMagic)
	copy(h.Version[:], HdrVersion)
	copy(h.Arch[:], HdrArchAMD64)

	tests := []struct {
		name    string
		modFunc func(h Header) Header
	}{
		{"Launch", func(h Header) Header {
			copy(h.Launch[:], "#!/usr/bin/env rm\n")
			return h
		}},
		{"Magic", func(h Header) Header {
			copy(h.Magic[:], "BAD_MAGIC")
			return h
		}},
		{"Version", func(h Header) Header {
			copy(h.Version[:], "02")
			return h
		}},
		{"Arch", func(h Header) Header {
			copy(h.Arch[:], HdrArchS390x)
			return h
		}},
		{"ID", func(h Header) Header {
			h.ID[0]++
			return h
		}},
		{"Ctime", func(h Header) Header {
			h.Ctime++
			return h
		}},
		{"Mtime", func(h Header) Header {
			h.Mtime++
			return h
		}},
		{"Dfree", func(h Header) Header {
			h.Dfree++
			return h
		}},
		{"Dtotal", func(h Header) Header {
			h.Dtotal++
			return h
		}},
		{"Descroff", func(h Header) Header {
			h.Descroff++
			return h
		}},
		{"Descrlen", func(h Header) Header {
			h.Descrlen++
			return h
		}},
		{"Dataoff", func(h Header) Header {
			h.Dataoff++
			return h
		}},
		{"Datalen", func(h Header) Header {
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
