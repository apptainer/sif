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
	}
	copy(p.Arch[:], HdrArch386)

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

func TestDescriptor_GetHashType(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	sigs, err := fimg.GetDescriptors(
		WithDataType(DataSignature),
		WithGroupID(1),
	)
	if err != nil {
		t.Fatalf("failed to get descriptors: %v", err)
	}

	if len(sigs) != 1 {
		t.Error("multiple signatures found where expecting 1")
	}

	hashtype, err := sigs[0].GetHashType()
	if err != nil {
		t.Error("sigs[0].GetHashType()", err)
	}

	if hashtype != HashSHA384 {
		t.Error("sig.GetHashType() should have returned 'HashSHA384'")
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestDescriptor_GetEntity(t *testing.T) {
	expected := []byte{159, 43, 108, 54, 217, 153, 163, 233, 28, 179, 16, 71, 32, 103, 21, 144, 193, 45, 66, 34}

	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	sigs, err := fimg.GetDescriptors(
		WithDataType(DataSignature),
		WithGroupID(1),
	)
	if err != nil {
		t.Fatalf("failed to get descriptors: %v", err)
	}

	if len(sigs) != 1 {
		t.Error("multiple signatures found where expecting 1")
	}

	entity, err := sigs[0].GetEntity()
	if err != nil {
		t.Error("sigs[0].GetEntity()", err)
	}

	if bytes.Equal(expected, entity[:len(expected)]) == false {
		t.Error("sig.GetEntity(): didn't get the expected entity, got:", entity[:len(expected)])
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestDescriptor_GetEntityString(t *testing.T) {
	expected := "9F2B6C36D999A3E91CB3104720671590C12D4222"

	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	sigs, err := fimg.GetDescriptors(
		WithDataType(DataSignature),
		WithGroupID(1),
	)
	if err != nil {
		t.Fatalf("failed to get descriptors: %v", err)
	}

	if len(sigs) != 1 {
		t.Error("multiple signatures found where expecting 1")
	}

	entity, err := sigs[0].GetEntityString()
	if err != nil {
		t.Error("sigs[0].GetEntityString()", err)
	}

	if expected != entity {
		t.Error("sig.GetEntityString(): didn't get the expected entity")
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
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
