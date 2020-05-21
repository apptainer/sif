// Copyright (c) 2020, Sylabs Inc. All rights reserved.
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
	"testing"

	uuid "github.com/satori/go.uuid"
	"github.com/sylabs/sif/pkg/sif"
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

			if err := verifyGolden(t.Name(), &b); err != nil {
				t.Errorf("failed to verify golden: %v", err)
			}
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
		name    string
		modFunc func(ood sif.Descriptor) sif.Descriptor
	}{
		{"Datatype", func(od sif.Descriptor) sif.Descriptor {
			od.Datatype = sif.DataEnvVar
			return od
		}},
		{"Used", func(od sif.Descriptor) sif.Descriptor {
			od.Used = !od.Used
			return od
		}},
		{"ID", func(od sif.Descriptor) sif.Descriptor {
			od.ID++
			return od
		}},
		{"Groupid", func(od sif.Descriptor) sif.Descriptor {
			od.Groupid++
			return od
		}},
		{"Link", func(od sif.Descriptor) sif.Descriptor {
			od.Link++
			return od
		}},
		{"Fileoff", func(od sif.Descriptor) sif.Descriptor {
			od.Fileoff++
			return od
		}},
		{"Filelen", func(od sif.Descriptor) sif.Descriptor {
			od.Filelen++
			return od
		}},
		{"Storelen", func(od sif.Descriptor) sif.Descriptor {
			od.Storelen++
			return od
		}},
		{"Ctime", func(od sif.Descriptor) sif.Descriptor {
			od.Ctime++
			return od
		}},
		{"Mtime", func(od sif.Descriptor) sif.Descriptor {
			od.Mtime++
			return od
		}},
		{"UID", func(od sif.Descriptor) sif.Descriptor {
			od.UID++
			return od
		}},
		{"Gid", func(od sif.Descriptor) sif.Descriptor {
			od.Gid++
			return od
		}},
		{"Name", func(od sif.Descriptor) sif.Descriptor {
			copy(od.Name[:], "BAD_NAME")
			return od
		}},
		{"Extra", func(od sif.Descriptor) sif.Descriptor {
			copy(od.Extra[:], "BAD_EXTRA")
			return od
		}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}

			od := tt.modFunc(od)
			if err := writeDescriptor(&b, od); err != nil {
				t.Fatal(err)
			}

			if err := verifyGolden(t.Name(), &b); err != nil {
				t.Errorf("failed to verify golden: %v", err)
			}
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

				if err := verifyGolden(t.Name(), &b); err != nil {
					t.Errorf("failed to verify golden: %v", err)
				}
			}
		})
	}
}
