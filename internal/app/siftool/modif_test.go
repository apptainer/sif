// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"bytes"
	"crypto"
	"errors"
	"os"
	"testing"

	"github.com/apptainer/sif/v2/pkg/sif"
)

func TestApp_New(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	tf, err := os.CreateTemp("", "sif-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	tf.Close()

	if err := a.New(tf.Name()); err != nil {
		t.Fatal(err)
	}
}

func TestApp_Add(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	tests := []struct {
		name     string
		data     []byte
		dataType sif.DataType
		opts     []sif.DescriptorInputOpt
		wantErr  error
	}{
		{
			name:     "DataPartition",
			data:     []byte{0xde, 0xad, 0xbe, 0xef},
			dataType: sif.DataPartition,
			opts: []sif.DescriptorInputOpt{
				sif.OptPartitionMetadata(sif.FsSquash, sif.PartPrimSys, "386"),
			},
		},
		{
			name:     "DataSignature",
			data:     []byte{0xde, 0xad, 0xbe, 0xef},
			dataType: sif.DataSignature,
			opts: []sif.DescriptorInputOpt{
				sif.OptSignatureMetadata(crypto.SHA256, []byte{
					0x12, 0x04, 0x5c, 0x8c, 0x0b, 0x10, 0x04, 0xd0, 0x58, 0xde,
					0x4b, 0xed, 0xa2, 0x0c, 0x27, 0xee, 0x7f, 0xf7, 0xba, 0x84,
				}),
			},
		},
		{
			name:     "CryptoMessage",
			data:     []byte{0xde, 0xad, 0xbe, 0xef},
			dataType: sif.DataCryptoMessage,
			opts: []sif.DescriptorInputOpt{
				sif.OptCryptoMessageMetadata(sif.FormatOpenPGP, sif.MessageClearSignature),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf, err := os.CreateTemp("", "sif-test-*")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tf.Name())
			tf.Close()

			if err := a.New(tf.Name()); err != nil {
				t.Fatal(err)
			}

			data := bytes.NewReader(tt.data)
			if got, want := a.Add(tf.Name(), tt.dataType, data, tt.opts...), tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}
		})
	}
}

func TestApp_Del(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	tf, err := os.CreateTemp("", "sif-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	tf.Close()

	if err := a.New(tf.Name()); err != nil {
		t.Fatal(err)
	}

	err = a.Add(tf.Name(), sif.DataGeneric, bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef}))
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Del(tf.Name(), 1); err != nil {
		t.Fatal(err)
	}
}

func TestApp_Setprim(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	tf, err := os.CreateTemp("", "sif-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	tf.Close()

	if err := a.New(tf.Name()); err != nil {
		t.Fatal(err)
	}

	err = a.Add(tf.Name(), sif.DataPartition, bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef}),
		sif.OptPartitionMetadata(sif.FsSquash, sif.PartSystem, "386"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Setprim(tf.Name(), 1); err != nil {
		t.Fatal(err)
	}
}
