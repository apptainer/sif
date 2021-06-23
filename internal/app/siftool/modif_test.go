// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/sylabs/sif/v2/pkg/sif"
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
		name    string
		opts    AddOptions
		wantErr error
	}{
		{
			name: "DataPartition",
			opts: AddOptions{
				Datatype: sif.DataPartition,
				Parttype: sif.PartPrimSys,
				Partfs:   sif.FsSquash,
				Partarch: sif.HdrArch386,
				Fp:       bytes.NewBuffer([]byte{0xde, 0xad, 0xbe, 0xef}),
			},
		},
		{
			name: "DataSignature",
			opts: AddOptions{
				Datatype:   sif.DataSignature,
				Signhash:   sif.HashSHA256,
				Signentity: "12045C8C0B1004D058DE4BEDA20C27EE7FF7BA84",
				Fp:         bytes.NewBuffer([]byte{0xde, 0xad, 0xbe, 0xef}),
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

			if got, want := a.Add(tf.Name(), tt.opts), tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}
		})
	}
}
