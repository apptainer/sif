// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hpcng/sif/pkg/sif" //nolint:staticcheck // In use until v2 API
	uuid "github.com/satori/go.uuid"
	"github.com/sebdah/goldie/v2"
)

func TestWriteHeader(t *testing.T) {
	h := sif.Header{
		ID:    uuid.UUID{0xb2, 0x65, 0x9d, 0x4e, 0xbd, 0x50, 0x4e, 0xa5, 0xbd, 0x17, 0xee, 0xc5, 0xe5, 0x4f, 0x91, 0x8e},
		Ctime: 1504657553,
		Mtime: 1504657653,
	}
	copy(h.Launch[:], sif.HdrLaunch)
	copy(h.Magic[:], sif.HdrMagic)
	copy(h.Version[:], sif.HdrVersion)
	copy(h.Arch[:], sif.HdrArchAMD64)

	tests := []struct {
		name    string
		modFunc func(h sif.Header) sif.Header
	}{
		{"Launch", func(h sif.Header) sif.Header {
			copy(h.Launch[:], "#!/usr/bin/env rm\n")
			return h
		}},
		{"Magic", func(h sif.Header) sif.Header {
			copy(h.Magic[:], "BAD_MAGIC")
			return h
		}},
		{"Version", func(h sif.Header) sif.Header {
			copy(h.Version[:], "02")
			return h
		}},
		{"Arch", func(h sif.Header) sif.Header {
			copy(h.Arch[:], sif.HdrArchS390x)
			return h
		}},
		{"ID", func(h sif.Header) sif.Header {
			h.ID[0]++
			return h
		}},
		{"Ctime", func(h sif.Header) sif.Header {
			h.Ctime++
			return h
		}},
		{"Mtime", func(h sif.Header) sif.Header {
			h.Mtime++
			return h
		}},
		{"Dfree", func(h sif.Header) sif.Header {
			h.Dfree++
			return h
		}},
		{"Dtotal", func(h sif.Header) sif.Header {
			h.Dtotal++
			return h
		}},
		{"Descroff", func(h sif.Header) sif.Header {
			h.Descroff++
			return h
		}},
		{"Descrlen", func(h sif.Header) sif.Header {
			h.Descrlen++
			return h
		}},
		{"Dataoff", func(h sif.Header) sif.Header {
			h.Dataoff++
			return h
		}},
		{"Datalen", func(h sif.Header) sif.Header {
			h.Datalen++
			return h
		}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}
			if err := writeHeader(&b, tt.modFunc(h)); err != nil {
				t.Fatal(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}

func TestWriteDescriptor(t *testing.T) {
	od := sif.Descriptor{
		Datatype: sif.DataDeffile,
		Used:     true,
		ID:       1,
		Groupid:  sif.DescrGroupMask | 1,
		Ctime:    1504657553,
		Mtime:    1504657553,
		UID:      1000,
		Gid:      1000,
	}
	copy(od.Name[:], "GOOD_NAME")
	copy(od.Extra[:], "GOOD_EXTRA")

	tests := []struct {
		name       string
		relativeID uint32
		modFunc    func(*sif.Descriptor)
	}{
		{
			name:    "Datatype",
			modFunc: func(od *sif.Descriptor) { od.Datatype = sif.DataEnvVar },
		},
		{
			name:    "Used",
			modFunc: func(od *sif.Descriptor) { od.Used = !od.Used },
		},
		{
			name:    "ID",
			modFunc: func(od *sif.Descriptor) { od.ID++ },
		},
		{
			name:       "RelativeID",
			relativeID: 1,
		},
		{
			name:    "Groupid",
			modFunc: func(od *sif.Descriptor) { od.Groupid++ },
		},
		{
			name:    "Link",
			modFunc: func(od *sif.Descriptor) { od.Link++ },
		},
		{
			name:    "Fileoff",
			modFunc: func(od *sif.Descriptor) { od.Fileoff++ },
		},
		{
			name:    "Filelen",
			modFunc: func(od *sif.Descriptor) { od.Filelen++ },
		},
		{
			name:    "Storelen",
			modFunc: func(od *sif.Descriptor) { od.Storelen++ },
		},
		{
			name:    "Ctime",
			modFunc: func(od *sif.Descriptor) { od.Ctime++ },
		},
		{
			name:    "Mtime",
			modFunc: func(od *sif.Descriptor) { od.Mtime++ },
		},
		{
			name:    "UID",
			modFunc: func(od *sif.Descriptor) { od.UID++ },
		},
		{
			name:    "Gid",
			modFunc: func(od *sif.Descriptor) { od.Gid++ },
		},
		{
			name:    "Name",
			modFunc: func(od *sif.Descriptor) { copy(od.Name[:], "BAD_NAME") },
		},
		{
			name:    "Extra",
			modFunc: func(od *sif.Descriptor) { copy(od.Extra[:], "BAD_EXTRA") },
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			od := od
			if tt.modFunc != nil {
				tt.modFunc(&od)
			}

			b := bytes.Buffer{}
			if err := writeDescriptor(&b, tt.relativeID, od); err != nil {
				t.Fatal(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}

func TestGetHeaderMetadata(t *testing.T) {
	h := sif.Header{
		ID:    uuid.UUID{0xb2, 0x65, 0x9d, 0x4e, 0xbd, 0x50, 0x4e, 0xa5, 0xbd, 0x17, 0xee, 0xc5, 0xe5, 0x4f, 0x91, 0x8e},
		Ctime: 1504657553,
		Mtime: 1504657653,
	}
	copy(h.Launch[:], sif.HdrLaunch)
	copy(h.Magic[:], sif.HdrMagic)
	copy(h.Version[:], sif.HdrVersion)
	copy(h.Arch[:], sif.HdrArchAMD64)

	tests := []struct {
		name    string
		header  sif.Header
		hash    crypto.Hash
		wantErr error
	}{
		{name: "HashUnavailable", hash: crypto.MD4, wantErr: errHashUnavailable},
		{name: "HashUnsupported", hash: crypto.MD5, wantErr: errHashUnsupported},
		{name: "SHA1", header: h, hash: crypto.SHA1},
		{name: "SHA224", header: h, hash: crypto.SHA224},
		{name: "SHA256", header: h, hash: crypto.SHA256},
		{name: "SHA384", header: h, hash: crypto.SHA384},
		{name: "SHA512", header: h, hash: crypto.SHA512},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			md, err := getHeaderMetadata(tt.header, tt.hash)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				b := bytes.Buffer{}
				if err := json.NewEncoder(&b).Encode(md); err != nil {
					t.Fatal(err)
				}

				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
			}
		})
	}
}

func TestGetObjectMetadata(t *testing.T) {
	od := sif.Descriptor{
		Datatype: sif.DataDeffile,
		Used:     true,
		ID:       1,
	}

	tests := []struct {
		name       string
		relativeID uint32
		od         sif.Descriptor
		r          io.Reader
		hash       crypto.Hash
		wantErr    error
	}{
		{name: "HashUnavailable", hash: crypto.MD4, wantErr: errHashUnavailable},
		{name: "HashUnsupported", hash: crypto.MD5, wantErr: errHashUnsupported},
		{name: "RelativeID", relativeID: 1, od: od, r: strings.NewReader("blah"), hash: crypto.SHA1},
		{name: "SHA1", od: od, r: strings.NewReader("blah"), hash: crypto.SHA1},
		{name: "SHA224", od: od, r: strings.NewReader("blah"), hash: crypto.SHA224},
		{name: "SHA256", od: od, r: strings.NewReader("blah"), hash: crypto.SHA256},
		{name: "SHA384", od: od, r: strings.NewReader("blah"), hash: crypto.SHA384},
		{name: "SHA512", od: od, r: strings.NewReader("blah"), hash: crypto.SHA512},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			md, err := getObjectMetadata(tt.relativeID, tt.od, tt.r, tt.hash)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				b := bytes.Buffer{}
				if err := json.NewEncoder(&b).Encode(md); err != nil {
					t.Fatal(err)
				}

				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
			}
		})
	}
}

func TestGetImageMetadata(t *testing.T) {
	f, err := sif.LoadContainer(filepath.Join("testdata", "images", "one-group.sif"), true)
	if err != nil {
		t.Fatal(err)
	}

	od1, _, err := f.GetFromDescrID(1)
	if err != nil {
		t.Fatal(err)
	}

	od2, _, err := f.GetFromDescrID(2)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		minID   uint32
		ods     []*sif.Descriptor
		hash    crypto.Hash
		wantErr error
	}{
		{name: "HashUnavailable", hash: crypto.MD4, wantErr: errHashUnavailable},
		{name: "HashUnsupported", hash: crypto.MD5, wantErr: errHashUnsupported},
		{name: "MinimumIDInvalid", minID: 2, ods: []*sif.Descriptor{od1}, hash: crypto.SHA1, wantErr: errMinimumIDInvalid},
		{name: "Object1", minID: 1, ods: []*sif.Descriptor{od1}, hash: crypto.SHA1},
		{name: "Object2", minID: 1, ods: []*sif.Descriptor{od2}, hash: crypto.SHA1},
		{name: "SHA1", minID: 1, ods: []*sif.Descriptor{od1, od2}, hash: crypto.SHA1},
		{name: "SHA224", minID: 1, ods: []*sif.Descriptor{od1, od2}, hash: crypto.SHA224},
		{name: "SHA256", minID: 1, ods: []*sif.Descriptor{od1, od2}, hash: crypto.SHA256},
		{name: "SHA384", minID: 1, ods: []*sif.Descriptor{od1, od2}, hash: crypto.SHA384},
		{name: "SHA512", minID: 1, ods: []*sif.Descriptor{od1, od2}, hash: crypto.SHA512},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			md, err := getImageMetadata(&f, tt.minID, tt.ods, tt.hash)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				b := bytes.Buffer{}
				if err := json.NewEncoder(&b).Encode(md); err != nil {
					t.Fatal(err)
				}

				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
			}
		})
	}
}
