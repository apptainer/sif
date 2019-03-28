// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"testing"
)

func TestFmtHeader(t *testing.T) {
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error(`LoadContainer("testdata/testcontainer2.sif", true):`, err)
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			t.Errorf("Error unloading container: %v", err)
		}
	}()

	t.Log(fimg.FmtHeader())
}

func TestFmtDescrList(t *testing.T) {
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error(`LoadContainer("testdata/testcontainer2.sif", true):`, err)
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			t.Errorf("Error unloading container: %v", err)
		}
	}()

	t.Log(fimg.FmtDescrList())
}

func TestFmtDescrInfo(t *testing.T) {
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error(`LoadContainer("testdata/testcontainer2.sif", true):`, err)
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			t.Errorf("Error unloading container: %v", err)
		}
	}()

	t.Log(fimg.FmtDescrInfo(1))
	t.Log(fimg.FmtDescrInfo(2))
	t.Log(fimg.FmtDescrInfo(3))
	t.Log(fimg.FmtDescrInfo(4))
}
