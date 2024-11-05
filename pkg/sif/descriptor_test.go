// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2018-2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sebdah/goldie/v2"
)

func TestDescriptor_GetData(t *testing.T) {
	f, err := LoadContainerFromPath(
		filepath.Join(corpus, "one-group-signed-pgp.sif"),
		OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatalf("failed to load container: %v", err)
	}
	defer func() {
		if err := f.UnloadContainer(); err != nil {
			t.Error(err)
		}
	}()

	// Get the signature block
	descr, err := f.GetDescriptor(WithID(3))
	if err != nil {
		t.Fatalf("failed to get descriptor: %v", err)
	}

	b, err := descr.GetData()
	if err != nil {
		t.Fatalf("failed to get data: %v", err)
	}

	if got, want := string(b[5:10]), "BEGIN"; got != want {
		t.Errorf("got data %#v, want %#v", got, want)
	}
}

func TestDescriptor_GetReader(t *testing.T) {
	f, err := LoadContainerFromPath(
		filepath.Join(corpus, "one-group-signed-pgp.sif"),
		OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatalf("failed to load container: %v", err)
	}
	defer func() {
		if err := f.UnloadContainer(); err != nil {
			t.Error(err)
		}
	}()

	// Get the signature block
	descr, err := f.GetDescriptor(WithID(3))
	if err != nil {
		t.Fatalf("failed to get descriptor: %v", err)
	}

	// Read data via Reader and validate data.
	b := make([]byte, descr.Size())
	if _, err := io.ReadFull(descr.GetReader(), b); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if got, want := string(b[5:10]), "BEGIN"; got != want {
		t.Errorf("got data %#v, want %#v", got, want)
	}
}

func TestDescriptor_Name(t *testing.T) {
	// load the test container
	f, err := LoadContainerFromPath(
		filepath.Join(corpus, "one-object-generic-json.sif"),
		OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatalf("failed to load container: %v", err)
	}

	part, err := f.GetDescriptor(WithDataType(DataGenericJSON))
	if err != nil {
		t.Fatalf("failed to get descriptor: %v", err)
	}

	if got, want := part.Name(), "data.json"; got != want {
		t.Errorf("got name %v, want %v", got, want)
	}

	// unload the test container
	if err = f.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

type testMetadata struct {
	Value int
}

func (m testMetadata) MarshalBinary() ([]byte, error) {
	return json.Marshal(m)
}

func (m *testMetadata) UnmarshalBinary(b []byte) error {
	return json.Unmarshal(bytes.TrimRight(b, "\x00"), m)
}

func TestDescriptor_GetMetadata(t *testing.T) {
	md := testMetadata{100}

	rd := rawDescriptor{
		DataType: DataGeneric,
	}
	if err := rd.setExtra(md); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		rd      rawDescriptor
		wantMD  testMetadata
		wantErr error
	}{
		{
			name:   "OK",
			rd:     rd,
			wantMD: md,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Descriptor{raw: tt.rd}

			var md testMetadata

			if got, want := d.GetMetadata(&md), tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if got, want := md, tt.wantMD; !reflect.DeepEqual(got, want) {
				t.Fatalf("got metadata %v, want %v", got, want)
			}
		})
	}
}

func TestDescriptor_PartitionMetadata(t *testing.T) {
	p := partition{
		Fstype:   FsSquash,
		Parttype: PartPrimSys,
		Arch:     hdrArch386,
	}

	rd := rawDescriptor{
		DataType: DataPartition,
	}
	if err := rd.setExtra(p); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		rd       rawDescriptor
		p        partition
		wantFS   FSType
		wantPart PartType
		wantArch string
		wantErr  error
	}{
		{
			name: "UnexpectedDataType",
			rd: rawDescriptor{
				DataType: DataGeneric,
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, []DataType{DataPartition}},
		},
		{
			name:     "PartPrimSys",
			rd:       rd,
			wantFS:   FsSquash,
			wantPart: PartPrimSys,
			wantArch: "386",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Descriptor{raw: tt.rd}

			fs, part, arch, err := d.PartitionMetadata()

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := fs, tt.wantFS; got != want {
					t.Fatalf("got filesystem type %v, want %v", got, want)
				}

				if got, want := part, tt.wantPart; got != want {
					t.Fatalf("got partition type %v, want %v", got, want)
				}

				if got, want := arch, tt.wantArch; got != want {
					t.Fatalf("got architecture %v, want %v", got, want)
				}
			}
		})
	}
}

func TestDescriptor_SignatureMetadata(t *testing.T) {
	tests := []struct {
		name    string
		dt      DataType
		ht      hashType
		fp      []byte
		wantErr error
		wantHT  crypto.Hash
	}{
		{
			name:    "UnexpectedDataType",
			dt:      DataGeneric,
			wantErr: &unexpectedDataTypeError{DataGeneric, []DataType{DataSignature}},
		},
		{
			name: "Fingerprint",
			dt:   DataSignature,
			ht:   hashSHA384,
			fp: []byte{
				0x12, 0x04, 0x5c, 0x8c, 0x0b, 0x10, 0x04, 0xd0, 0x58, 0xde,
				0x4b, 0xed, 0xa2, 0x0c, 0x27, 0xee, 0x7f, 0xf7, 0xba, 0x84,
			},
			wantHT: crypto.SHA384,
		},
		{
			name:   "NoFingerprint",
			dt:     DataSignature,
			ht:     hashSHA256,
			wantHT: crypto.SHA256,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := signature{
				Hashtype: tt.ht,
			}
			copy(sig.Entity[:], tt.fp)

			rd := rawDescriptor{
				DataType: tt.dt,
			}
			if err := rd.setExtra(binaryMarshaler{sig}); err != nil {
				t.Fatal(err)
			}

			d := Descriptor{raw: rd}

			ht, fp, err := d.SignatureMetadata()

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := ht, tt.wantHT; got != want {
					t.Fatalf("got hash type %v, want %v", got, want)
				}

				if got, want := fp, tt.fp; !bytes.Equal(got, want) {
					t.Fatalf("got entity %v, want %v", got, want)
				}
			}
		})
	}
}

func TestDescriptor_CryptoMessageMetadata(t *testing.T) {
	m := cryptoMessage{
		Formattype:  FormatOpenPGP,
		Messagetype: MessageClearSignature,
	}

	rd := rawDescriptor{
		DataType: DataCryptoMessage,
	}
	if err := rd.setExtra(binaryMarshaler{m}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		rd      rawDescriptor
		wantFT  FormatType
		wantMT  MessageType
		wantErr error
	}{
		{
			name: "UnexpectedDataType",
			rd: rawDescriptor{
				DataType: DataGeneric,
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, []DataType{DataCryptoMessage}},
		},
		{
			name:   "OK",
			rd:     rd,
			wantFT: FormatOpenPGP,
			wantMT: MessageClearSignature,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Descriptor{raw: tt.rd}

			ft, mt, err := d.CryptoMessageMetadata()

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := ft, tt.wantFT; got != want {
					t.Fatalf("got format type %v, want %v", got, want)
				}

				if got, want := mt, tt.wantMT; got != want {
					t.Fatalf("got message type %v, want %v", got, want)
				}
			}
		})
	}
}

func TestDescriptor_SBOMMetadata(t *testing.T) {
	m := sbom{
		Format: SBOMFormatCycloneDXJSON,
	}

	rd := rawDescriptor{
		DataType: DataSBOM,
	}
	if err := rd.setExtra(binaryMarshaler{m}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		rd         rawDescriptor
		wantFormat SBOMFormat
		wantErr    error
	}{
		{
			name: "UnexpectedDataType",
			rd: rawDescriptor{
				DataType: DataGeneric,
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, []DataType{DataSBOM}},
		},
		{
			name:       "OK",
			rd:         rd,
			wantFormat: SBOMFormatCycloneDXJSON,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Descriptor{raw: tt.rd}

			f, err := d.SBOMMetadata()

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := f, tt.wantFormat; got != want {
					t.Fatalf("got format %v, want %v", got, want)
				}
			}
		})
	}
}

func TestDescriptor_OCIBlobMetadata(t *testing.T) {
	rd := rawDescriptor{
		DataType: DataOCIBlob,
	}
	if err := rd.setExtra(newOCIBlobDigest()); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		rd         rawDescriptor
		wantDigest v1.Hash
		wantErr    error
	}{
		{
			name: "UnexpectedDataType",
			rd: rawDescriptor{
				DataType: DataGeneric,
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, []DataType{DataOCIBlob, DataOCIRootIndex}},
		},
		{
			name: "OK",
			rd:   rd,
			wantDigest: v1.Hash{
				Algorithm: "sha256",
				Hex:       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Descriptor{raw: tt.rd}

			h, err := d.OCIBlobDigest()

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if got, want := h, tt.wantDigest; got != want {
				t.Fatalf("got digest %v, want %v", got, want)
			}
		})
	}
}

func TestDescriptor_GetIntegrityReader(t *testing.T) {
	rd := rawDescriptor{
		DataType:   DataDeffile,
		Used:       true,
		ID:         1,
		GroupID:    descrGroupMask | 1,
		CreatedAt:  1504657553,
		ModifiedAt: 1504657553,
	}
	copy(rd.Name[:], "GOOD_NAME")
	copy(rd.Extra[:], "GOOD_EXTRA")

	tests := []struct {
		name       string
		relativeID uint32
		modFunc    func(*rawDescriptor)
	}{
		{
			name:    "DataType",
			modFunc: func(od *rawDescriptor) { od.DataType = DataEnvVar },
		},
		{
			name:    "Used",
			modFunc: func(od *rawDescriptor) { od.Used = !od.Used },
		},
		{
			name:    "ID",
			modFunc: func(od *rawDescriptor) { od.ID++ },
		},
		{
			name:       "RelativeID",
			relativeID: 1,
		},
		{
			name:    "GroupID",
			modFunc: func(od *rawDescriptor) { od.GroupID++ },
		},
		{
			name:    "LinkedID",
			modFunc: func(od *rawDescriptor) { od.LinkedID++ },
		},
		{
			name:    "Offset",
			modFunc: func(od *rawDescriptor) { od.Offset++ },
		},
		{
			name:    "Size",
			modFunc: func(od *rawDescriptor) { od.Size++ },
		},
		{
			name:    "SizeWithPadding",
			modFunc: func(od *rawDescriptor) { od.SizeWithPadding++ },
		},
		{
			name:    "CreatedAt",
			modFunc: func(od *rawDescriptor) { od.CreatedAt++ },
		},
		{
			name:    "ModifiedAt",
			modFunc: func(od *rawDescriptor) { od.ModifiedAt++ },
		},
		{
			name:    "UID",
			modFunc: func(od *rawDescriptor) { od.UID++ },
		},
		{
			name:    "GID",
			modFunc: func(od *rawDescriptor) { od.GID++ },
		},
		{
			name:    "Name",
			modFunc: func(od *rawDescriptor) { copy(od.Name[:], "BAD_NAME") },
		},
		{
			name:    "Extra",
			modFunc: func(od *rawDescriptor) { copy(od.Extra[:], "BAD_EXTRA") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Descriptor{
				raw:        rd,
				relativeID: tt.relativeID,
			}
			if tt.modFunc != nil {
				tt.modFunc(&d.raw)
			}

			b := bytes.Buffer{}

			if _, err := io.Copy(&b, d.GetIntegrityReader()); err != nil {
				t.Fatal(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}
