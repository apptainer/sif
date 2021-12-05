// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"path/filepath"
	"testing"
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

			runCommand(t, cmd, args)
		})
	}
}
