// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/sebdah/goldie/v2"
)

func TestDescriptor_GetData(t *testing.T) {
	bufferedImage, err := LoadContainer(filepath.Join("testdata", "testcontainer2.sif"), true)
	if err != nil {
		t.Fatalf("failed to load container: %v", err)
	}
	defer func() {
		if err := bufferedImage.UnloadContainer(); err != nil {
			t.Error(err)
		}
	}()

	tests := []struct {
		name string
		fimg *FileImage
	}{
		{"Buffered", &bufferedImage},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Get the signature block
			descr, err := tt.fimg.GetDescriptor(WithID(3))
			if err != nil {
				t.Fatalf("failed to get descriptor: %v", err)
			}

			b, err := descr.GetData(tt.fimg)
			if err != nil {
				t.Fatalf("failed to get data: %v", err)
			}

			if got, want := string(b[5:10]), "BEGIN"; got != want {
				t.Errorf("got data %#v, want %#v", got, want)
			}
		})
	}
}

func TestDescriptor_GetReader(t *testing.T) {
	bufferedImage, err := LoadContainer(filepath.Join("testdata", "testcontainer2.sif"), true)
	if err != nil {
		t.Fatalf("failed to load container: %v", err)
	}
	defer func() {
		if err := bufferedImage.UnloadContainer(); err != nil {
			t.Error(err)
		}
	}()

	tests := []struct {
		name string
		fimg *FileImage
	}{
		{"Buffered", &bufferedImage},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Get the signature block
			descr, err := tt.fimg.GetDescriptor(WithID(3))
			if err != nil {
				t.Fatalf("failed to get descriptor: %v", err)
			}

			// Read data via Reader and validate data.
			b := make([]byte, descr.Filelen)
			if _, err := io.ReadFull(descr.GetReader(tt.fimg), b); err != nil {
				t.Fatalf("failed to read: %v", err)
			}
			if got, want := string(b[5:10]), "BEGIN"; got != want {
				t.Errorf("got data %#v, want %#v", got, want)
			}
		})
	}
}

func TestDescriptor_GetName(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	parts, err := fimg.GetDescriptors(
		WithDataType(DataPartition),
		WithGroupID(1),
	)
	if err != nil {
		t.Fatalf("failed to get descriptors: %v", err)
	}

	if len(parts) != 1 {
		t.Error("multiple partitions found where expecting 1")
	}

	if parts[0].GetName() != "busybox.squash" {
		t.Error(`parts[0].GetName() != "busybox.squash"`)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestDescriptor_GetPartitionMetadata(t *testing.T) {
	p := partition{
		Fstype:   FsSquash,
		Parttype: PartPrimSys,
		Arch:     hdrArch386,
	}

	rd := rawDescriptor{
		Datatype: DataPartition,
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
				Datatype: DataGeneric,
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, DataPartition},
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
			fs, part, arch, err := tt.rd.GetPartitionMetadata()

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

func TestDescriptor_GetSignatureMetadata(t *testing.T) {
	s := signature{
		Hashtype: HashSHA384,
	}
	copy(s.Entity[:], []byte{
		0x12, 0x04, 0x5c, 0x8c, 0x0b, 0x10, 0x04, 0xd0, 0x58, 0xde,
		0x4b, 0xed, 0xa2, 0x0c, 0x27, 0xee, 0x7f, 0xf7, 0xba, 0x84,
	})

	rd := rawDescriptor{
		Datatype: DataSignature,
	}
	if err := rd.setExtra(s); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		rd      rawDescriptor
		wantHT  HashType
		wantFP  [20]byte
		wantErr error
	}{
		{
			name: "UnexpectedDataType",
			rd: rawDescriptor{
				Datatype: DataGeneric,
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, DataSignature},
		},
		{
			name:   "OK",
			rd:     rd,
			wantHT: HashSHA384,
			wantFP: [...]byte{
				0x12, 0x04, 0x5c, 0x8c, 0x0b, 0x10, 0x04, 0xd0, 0x58, 0xde,
				0x4b, 0xed, 0xa2, 0x0c, 0x27, 0xee, 0x7f, 0xf7, 0xba, 0x84,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ht, fp, err := tt.rd.GetSignatureMetadata()

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := ht, tt.wantHT; got != want {
					t.Fatalf("got hash type %v, want %v", got, want)
				}

				if got, want := fp[:], tt.wantFP[:]; !bytes.Equal(got, want) {
					t.Fatalf("got entity %v, want %v", got, want)
				}
			}
		})
	}
}

func TestDescriptor_GetCryptoMessageMetadata(t *testing.T) {
	m := cryptoMessage{
		Formattype:  FormatOpenPGP,
		Messagetype: MessageClearSignature,
	}

	rd := rawDescriptor{
		Datatype: DataCryptoMessage,
	}
	if err := rd.setExtra(m); err != nil {
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
				Datatype: DataGeneric,
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, DataCryptoMessage},
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
			ft, mt, err := tt.rd.GetCryptoMessageMetadata()

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

func TestDescriptor_GetIntegrityReader(t *testing.T) {
	d := rawDescriptor{
		Datatype: DataDeffile,
		Used:     true,
		ID:       1,
		Groupid:  DescrGroupMask | 1,
		Ctime:    1504657553,
		Mtime:    1504657553,
	}
	copy(d.Name[:], "GOOD_NAME")
	copy(d.Extra[:], "GOOD_EXTRA")

	tests := []struct {
		name       string
		relativeID uint32
		modFunc    func(*rawDescriptor)
	}{
		{
			name:    "Datatype",
			modFunc: func(od *rawDescriptor) { od.Datatype = DataEnvVar },
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
			name:    "Groupid",
			modFunc: func(od *rawDescriptor) { od.Groupid++ },
		},
		{
			name:    "Link",
			modFunc: func(od *rawDescriptor) { od.Link++ },
		},
		{
			name:    "Fileoff",
			modFunc: func(od *rawDescriptor) { od.Fileoff++ },
		},
		{
			name:    "Filelen",
			modFunc: func(od *rawDescriptor) { od.Filelen++ },
		},
		{
			name:    "Storelen",
			modFunc: func(od *rawDescriptor) { od.Storelen++ },
		},
		{
			name:    "Ctime",
			modFunc: func(od *rawDescriptor) { od.Ctime++ },
		},
		{
			name:    "Mtime",
			modFunc: func(od *rawDescriptor) { od.Mtime++ },
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			d := d
			if tt.modFunc != nil {
				tt.modFunc(&d)
			}

			b := bytes.Buffer{}

			if _, err := io.Copy(&b, d.GetIntegrityReader(tt.relativeID)); err != nil {
				t.Fatal(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}
