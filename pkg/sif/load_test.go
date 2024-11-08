// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadContainerFromPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		opts []LoadOpt
	}{
		{
			name: "NoOpts",
			path: filepath.Join(corpus, "one-group.sif"),
		},
		{
			name: "ReadOnly",
			path: filepath.Join(corpus, "one-group.sif"),
			opts: []LoadOpt{OptLoadWithFlag(os.O_RDONLY)},
		},
		{
			name: "ReadWrite",
			path: filepath.Join(corpus, "one-group.sif"),
			opts: []LoadOpt{OptLoadWithFlag(os.O_RDWR)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := LoadContainerFromPath(tt.path, tt.opts...)
			if err != nil {
				t.Fatalf("failed to load container: %v", err)
			}

			if err := f.UnloadContainer(); err != nil {
				t.Errorf("failed to unload container: %v", err)
			}
		})
	}
}

func TestLoadContainer(t *testing.T) {
	tests := []struct {
		name string
		opts []LoadOpt
	}{
		{
			name: "NoOpts",
		},
		{
			name: "CloseOnUnload",
			opts: []LoadOpt{OptLoadWithCloseOnUnload(true)},
		},
		{
			name: "NoCloseOnUnload",
			opts: []LoadOpt{OptLoadWithCloseOnUnload(false)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw, err := os.Open(filepath.Join(corpus, "one-group.sif"))
			if err != nil {
				t.Fatal(err)
			}
			defer rw.Close()

			f, err := LoadContainer(rw, tt.opts...)
			if err != nil {
				t.Fatalf("failed to load container: %v", err)
			}

			if err := f.UnloadContainer(); err != nil {
				t.Errorf("failed to unload container: %v", err)
			}
		})
	}
}

func TestLoadContainerFpMock(t *testing.T) {
	// This test is using mockSifReadWriter to verify that the code
	// is not making assumptions regading the behavior of the
	// ReadWriter it's getting, as mockSifReadWriter implements a
	// very dumb buffer. This specific test could be exteded to test
	// for more error conditions as it would be possible to report
	// errors from cases where it would be otherwise hard to do so
	// (e.g. Seek, ReadAt or Truncate reporting errors).

	// Load a valid SIF file to test the happy path.
	content, err := os.ReadFile(filepath.Join(corpus, "one-group.sif"))
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	rw := NewBuffer(content)

	fimg, err := LoadContainer(rw, OptLoadWithFlag(os.O_RDONLY))
	if err != nil {
		t.Error("LoadContainerFp(fp, true):", err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error("fimg.UnloadContainer():", err)
	}
}

func TestLoadContainerInvalidMagic(t *testing.T) {
	// Load a valid SIF file ...
	content, err := os.ReadFile(filepath.Join(corpus, "one-group.sif"))
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	// ... and edit the magic to make it invalid. Instead of
	// exploring all kinds of invalid, simply mess with the last
	// byte, as this would catch off-by-one errors in the code.
	copy(content[hdrLaunchLen:hdrLaunchLen+hdrMagicLen], "SIF_MAGIX")

	rw := NewBuffer(content)

	fimg, err := LoadContainer(rw, OptLoadWithFlag(os.O_RDONLY))
	if err == nil {
		// unload the container in case it's loaded, ignore
		// any errors
		_ = fimg.UnloadContainer()
		t.Errorf(`LoadContainerFp(fp, true) did not report an error for a container with invalid magic.`)
	}
}
