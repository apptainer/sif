// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/apptainer/sif/v2/pkg/sif"
)

func Test_command_getMount(t *testing.T) {
	if _, err := exec.LookPath("squashfuse"); err != nil {
		t.Skip("squashfuse not found, skipping mount tests")
	}

	tests := []struct {
		name    string
		opts    commandOpts
		path    string
		wantErr error
	}{
		{
			name:    "Empty",
			path:    filepath.Join(corpus, "empty.sif"),
			wantErr: sif.ErrNoObjects,
		},
		{
			name: "OneGroup",
			path: filepath.Join(corpus, "one-group.sif"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := os.MkdirTemp("", "siftool-mount-*")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cmd := exec.Command("fusermount", "-u", path)

				if err := cmd.Run(); err != nil {
					t.Log(err)
				}

				os.RemoveAll(path)
			})

			c := &command{opts: tt.opts}

			cmd := c.getMount()

			runCommand(t, cmd, []string{tt.path, path}, tt.wantErr)
		})
	}
}
