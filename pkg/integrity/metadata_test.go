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

	"github.com/hpcng/sif/v2/pkg/sif"
	"github.com/sebdah/goldie/v2"
)

func TestWriteDescriptor(t *testing.T) {
	od := sif.Descriptor{
		Datatype: sif.DataDeffile,
		Used:     true,
		ID:       1,
		Groupid:  sif.DescrGroupMask | 1,
		Ctime:    1504657553,
		Mtime:    1504657553,
		UID:      1000,
		GID:      1000,
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
			name:    "GID",
			modFunc: func(od *sif.Descriptor) { od.GID++ },
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
	// Byte stream that represents integrity-protected fields of an arbitrary image.
	b := []byte{
		0x23, 0x21, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x65,
		0x6e, 0x76, 0x20, 0x72, 0x75, 0x6e, 0x2d, 0x73, 0x69, 0x6e, 0x67, 0x75,
		0x6c, 0x61, 0x72, 0x69, 0x74, 0x79, 0x0a, 0x00, 0x53, 0x49, 0x46, 0x5f,
		0x4d, 0x41, 0x47, 0x49, 0x43, 0x00, 0x30, 0x31, 0x00, 0xb2, 0x65, 0x9d,
		0x4e, 0xbd, 0x50, 0x4e, 0xa5, 0xbd, 0x17, 0xee, 0xc5, 0xe5, 0x4f, 0x91,
		0x8e,
	}

	tests := []struct {
		name    string
		header  io.Reader
		hash    crypto.Hash
		wantErr error
	}{
		{name: "HashUnavailable", header: bytes.NewReader(b), hash: crypto.MD4, wantErr: errHashUnavailable},
		{name: "HashUnsupported", header: bytes.NewReader(b), hash: crypto.MD5, wantErr: errHashUnsupported},
		{name: "SHA1", header: bytes.NewReader(b), hash: crypto.SHA1},
		{name: "SHA224", header: bytes.NewReader(b), hash: crypto.SHA224},
		{name: "SHA256", header: bytes.NewReader(b), hash: crypto.SHA256},
		{name: "SHA384", header: bytes.NewReader(b), hash: crypto.SHA384},
		{name: "SHA512", header: bytes.NewReader(b), hash: crypto.SHA512},
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
