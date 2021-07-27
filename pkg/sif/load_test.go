// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadContainer(t *testing.T) {
	fimg, err := LoadContainerFromPath(
		filepath.Join("testdata", "testcontainer2.sif"),
		OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error("fimg.UnloadContainer():", err)
	}
}

func TestLoadContainerFp(t *testing.T) {
	tests := []struct {
		name   string
		offset int64
	}{
		{
			name: "NoSeek",
		},
		{
			name:   "Seek",
			offset: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp, err := os.Open("testdata/testcontainer2.sif")
			if err != nil {
				t.Fatal("error opening testdata/testcontainer2.sif:", err)
			}

			if _, err := fp.Seek(tt.offset, io.SeekStart); err != nil {
				t.Fatal(err)
			}

			fimg, err := LoadContainer(fp, OptLoadWithFlag(os.O_RDONLY))
			if err != nil {
				t.Error("LoadContainerFp(fp, true):", err)
			}

			if err = fimg.UnloadContainer(); err != nil {
				t.Error("fimg.UnloadContainer():", err)
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
	content, err := ioutil.ReadFile("testdata/testcontainer2.sif")
	if err != nil {
		t.Error(`ioutil.ReadFile("testdata/testcontainer2.sif"):`, err)
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
	content, err := ioutil.ReadFile("testdata/testcontainer2.sif")
	if err != nil {
		t.Error(`ioutil.ReadFile("testdata/testcontainer2.sif"):`, err)
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

func TestTrimZeroBytes(t *testing.T) {
	tt := []struct {
		name   string
		in     []byte
		expect string
	}{
		{
			name:   "no zero",
			in:     []byte("hello!"),
			expect: "hello!",
		},
		{
			name:   "c string x00",
			in:     []byte("hello!\x00"),
			expect: "hello!",
		},
		{
			name:   "c string 000",
			in:     []byte("hello!\000"),
			expect: "hello!",
		},
		{
			name:   "many zeroes x00",
			in:     []byte("hello!\x00\x00\x00\x00\x00\x00\x00"),
			expect: "hello!",
		},
		{
			name:   "many zeroes 000",
			in:     []byte("hello!\000\000\000\000\000\000\000"),
			expect: "hello!",
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			actual := trimZeroBytes(tc.in)
			if tc.expect != actual {
				t.Fatalf("Expected %q, but got %q", tc.expect, actual)
			}
		})
	}
}
