// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2022, Sylabs Inc. All rights reserved.
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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apptainer/sif/v2/pkg/sif"
	"github.com/sebdah/goldie/v2"
)

func TestGetHeaderMetadata(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "sources", "header.bin"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		header  io.Reader
		hash    crypto.Hash
		wantErr error
	}{
		{name: "HashUnavailable", header: bytes.NewReader(b), hash: crypto.MD4, wantErr: errHashUnavailable},
		{name: "HashUnsupportedMD5", header: bytes.NewReader(b), hash: crypto.MD5, wantErr: errHashUnsupported},
		{name: "HashUnsupportedSHA1", header: bytes.NewReader(b), hash: crypto.SHA1, wantErr: errHashUnsupported},
		{name: "SHA224", header: bytes.NewReader(b), hash: crypto.SHA224},
		{name: "SHA256", header: bytes.NewReader(b), hash: crypto.SHA256},
		{name: "SHA384", header: bytes.NewReader(b), hash: crypto.SHA384},
		{name: "SHA512", header: bytes.NewReader(b), hash: crypto.SHA512},
		{name: "SHA512_224", header: bytes.NewReader(b), hash: crypto.SHA512_224},
		{name: "SHA512_256", header: bytes.NewReader(b), hash: crypto.SHA512_256},
	}

	for _, tt := range tests {
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
	// Byte stream that represents integrity-protected fields of an arbitrary descriptor with
	// relative ID of zero.
	rid0, err := os.ReadFile(filepath.Join("testdata", "sources", "descr-rid0.bin"))
	if err != nil {
		t.Fatal(err)
	}

	// Byte stream that represents integrity-protected fields of an arbitrary descriptor with
	// relative ID of one.
	rid1, err := os.ReadFile(filepath.Join("testdata", "sources", "descr-rid1.bin"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		relativeID uint32
		descr      io.Reader
		data       io.Reader
		hash       crypto.Hash
		wantErr    error
	}{
		{name: "HashUnavailable", descr: bytes.NewReader(rid0), hash: crypto.MD4, wantErr: errHashUnavailable},
		{name: "HashUnsupportedMD5", descr: bytes.NewReader(rid0), hash: crypto.MD5, wantErr: errHashUnsupported},
		{name: "HashUnsupportedSHA1", descr: bytes.NewReader(rid0), hash: crypto.SHA1, wantErr: errHashUnsupported},
		{name: "RelativeID", relativeID: 1, descr: bytes.NewReader(rid1), data: strings.NewReader("blah"), hash: crypto.SHA256}, //nolint:lll
		{name: "SHA224", descr: bytes.NewReader(rid0), data: strings.NewReader("blah"), hash: crypto.SHA224},
		{name: "SHA256", descr: bytes.NewReader(rid0), data: strings.NewReader("blah"), hash: crypto.SHA256},
		{name: "SHA384", descr: bytes.NewReader(rid0), data: strings.NewReader("blah"), hash: crypto.SHA384},
		{name: "SHA512", descr: bytes.NewReader(rid0), data: strings.NewReader("blah"), hash: crypto.SHA512},
		{name: "SHA512_224", descr: bytes.NewReader(rid0), data: strings.NewReader("blah"), hash: crypto.SHA512_224},
		{name: "SHA512_256", descr: bytes.NewReader(rid0), data: strings.NewReader("blah"), hash: crypto.SHA512_256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md, err := getObjectMetadata(tt.relativeID, tt.descr, tt.data, tt.hash)
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
	f := loadContainer(t, filepath.Join(corpus, "one-group.sif"))

	od1, err := f.GetDescriptor(sif.WithID(1))
	if err != nil {
		t.Fatal(err)
	}

	od2, err := f.GetDescriptor(sif.WithID(2))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		minID   uint32
		ods     []sif.Descriptor
		hash    crypto.Hash
		wantErr error
	}{
		{name: "HashUnavailable", hash: crypto.MD4, wantErr: errHashUnavailable},
		{name: "HashUnsupportedMD5", hash: crypto.MD5, wantErr: errHashUnsupported},
		{name: "HashUnsupportedSHA1", hash: crypto.SHA1, wantErr: errHashUnsupported},
		{name: "MinimumIDInvalid", minID: 2, ods: []sif.Descriptor{od1}, hash: crypto.SHA256, wantErr: errMinimumIDInvalid},
		{name: "Object1", minID: 1, ods: []sif.Descriptor{od1}, hash: crypto.SHA256},
		{name: "Object2", minID: 1, ods: []sif.Descriptor{od2}, hash: crypto.SHA256},
		{name: "SHA224", minID: 1, ods: []sif.Descriptor{od1, od2}, hash: crypto.SHA224},
		{name: "SHA256", minID: 1, ods: []sif.Descriptor{od1, od2}, hash: crypto.SHA256},
		{name: "SHA384", minID: 1, ods: []sif.Descriptor{od1, od2}, hash: crypto.SHA384},
		{name: "SHA512", minID: 1, ods: []sif.Descriptor{od1, od2}, hash: crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md, err := getImageMetadata(f, tt.minID, tt.ods, tt.hash)
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
