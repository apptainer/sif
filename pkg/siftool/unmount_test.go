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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/apptainer/sif/v2/pkg/user"
)

func Test_command_getUnmount(t *testing.T) {
	if _, err := exec.LookPath("squashfuse"); err != nil {
		t.Skip(" not found, skipping unmount tests")
	}
	if _, err := exec.LookPath("fusermount"); err != nil {
		t.Skip(" not found, skipping unmount tests")
	}

	path, err := os.MkdirTemp("", "siftool-unmount-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.RemoveAll(path)
	})

	testSIF := filepath.Join(corpus, "one-group.sif")
	if err := user.Mount(context.Background(), testSIF, path); err != nil {
		t.Fatal(err)
	}

	c := &command{}
	cmd := c.getUnmount()
	runCommand(t, cmd, []string{path}, nil)
}
