// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"
)

func TestLoadContainer(t *testing.T) {
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error("fimg.UnloadContainer():", err)
	}
}

func TestLoadContainerFp(t *testing.T) {
	fp, err := os.Open("testdata/testcontainer2.sif")
	if err != nil {
		t.Error("error opening testdata/testcontainer2.sif:", err)
	}

	fimg, err := LoadContainerFp(fp, true)
	if err != nil {
		t.Error("LoadContainerFp(fp, true):", err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error("fimg.UnloadContainer():", err)
	}
}

func TestLoadContainerReader(t *testing.T) {
	content, err := ioutil.ReadFile("testdata/testcontainer2.sif")
	if err != nil {
		t.Error(`ioutil.ReadFile("testdata/testcontainer2.sif"):`, err)
	}

	// short read on the descriptor list, make sure it still work
	// and that DescrArr is set to nil (since not complete)
	r := bytes.NewReader(content[:31768])
	fimg, err := LoadContainerReader(r)
	if err != nil || fimg.DescrArr != nil {
		t.Error(`LoadContainerBuffer(buf):`, err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error(`fimg.UnloadContainer():`, err)
	}

	// this buffer is big enough to include header + complete DescrArr
	r = bytes.NewReader(content[:32768])
	fimg, err = LoadContainerReader(r)
	if err != nil {
		t.Error(`LoadContainerBuffer(buf):`, err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error(`fimg.UnloadContainer():`, err)
	}
}
