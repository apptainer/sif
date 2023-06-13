// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2021-2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sylabs/sif/v2/pkg/sif"
)

func Test_command_getAdd(t *testing.T) {
	tests := []struct {
		name  string
		opts  commandOpts
		flags []string
	}{
		{
			name: "DataPartition",
			flags: []string{
				"--datatype", "4",
				"--parttype", "2",
				"--partfs", "1",
				"--partarch", "1",
			},
		},
		{
			name: "DataSignature",
			flags: []string{
				"--datatype", "5",
				"--signhash", "1",
				"--signentity", "433FE984155206BD962725E20E8713472A879943",
			},
		},
		{
			name: "DataOCIRootIndex",
			flags: []string{
				"--datatype", "10",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &command{opts: tt.opts}

			cmd := c.getAdd()

			args := []string{
				makeTestSIF(t, false),
				filepath.Join("testdata", "input", "input.bin"),
			}
			args = append(args, tt.flags...)

			runCommand(t, cmd, args, nil)
		})
	}
}

func Test_getDigestFromInputFile(t *testing.T) {
	tests := []struct {
		name       string
		dataType   sif.DataType
		wantDigest string
	}{
		{
			name:       "OCIRootIndex",
			dataType:   sif.DataOCIRootIndex,
			wantDigest: "sha256:004dfc8da678c309de28b5386a1e9efd57f536b150c40d29b31506aa0fb17ec2",
		},
		{
			name:       "OCIBlob",
			dataType:   sif.DataOCIBlob,
			wantDigest: "sha256:004dfc8da678c309de28b5386a1e9efd57f536b150c40d29b31506aa0fb17ec2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", "input", "input.bin"))
			if err != nil {
				t.Fatal(err)
			}

			digest, err := getDigestFromInputFile(f)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := digest, tt.wantDigest; got != want {
				t.Errorf("digest got: %s, wanted: %s", got, want)
			}
		})
	}
}
