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

func Test_command_getInfo(t *testing.T) {
	tests := []struct {
		name string
		opts commandOpts
		id   string
		path string
	}{
		{
			name: "One",
			id:   "1",
			path: filepath.Join(corpus, "one-group-signed.sif"),
		},
		{
			name: "Two",
			id:   "2",
			path: filepath.Join(corpus, "one-group-signed.sif"),
		},
		{
			name: "Three",
			id:   "3",
			path: filepath.Join(corpus, "one-group-signed.sif"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &command{opts: tt.opts}

			cmd := c.getInfo()

			runCommand(t, cmd, []string{tt.id, tt.path})
		})
	}
}
