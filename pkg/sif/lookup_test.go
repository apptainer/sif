// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	//	"container/list"
	//	"encoding/binary"
	//	"github.com/satori/go.uuid"
	//	"os"
	"testing"
)

func TestGetHeader(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer.sif, true):", err)
	}

	header := fimg.GetHeader()
	if header == nil {
		t.Error("fimg.GetHeader(): returned nil")
	}

	if string(header.Magic[:9]) != "SIF_MAGIC" {
		t.Error("fimg.GetHeader(): wrong magic")
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}
