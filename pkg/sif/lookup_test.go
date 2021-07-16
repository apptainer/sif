// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"testing"
)

func TestGetFromDescrID(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	_, _, err = fimg.GetFromDescrID(1)
	if err != nil {
		t.Error("fimg.GetFromDescrID(): should have found descriptor")
	}

	_, _, err = fimg.GetFromDescrID(2)
	if err != nil {
		t.Error("fimg.GetFromDescrID(): should have found descriptor")
	}

	_, _, err = fimg.GetFromDescrID(3)
	if err != nil {
		t.Error("fimg.GetFromDescrID(): should have found descriptor")
	}

	_, _, err = fimg.GetFromDescrID(4)
	if err == nil {
		t.Error("fimg.GetFromDescrID(): should have NOT found descriptor")
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestGetSIFArch(t *testing.T) {
	if GetSIFArch("386") != HdrArch386 {
		t.Error(GetSIFArch("386") != HdrArch386)
	}
	if GetSIFArch("arm64") != HdrArchARM64 {
		t.Error(GetSIFArch("arm64") != HdrArchARM64)
	}
	if GetSIFArch("cray") != HdrArchUnknown {
		t.Error(GetSIFArch("cray") != HdrArchUnknown)
	}
}

func TestGetGoArch(t *testing.T) {
	if GetGoArch(HdrArch386) != "386" {
		t.Error(GetGoArch(HdrArch386) != "386")
	}
	if GetGoArch(HdrArchARM64) != "arm64" {
		t.Error(GetGoArch(HdrArchARM64) != "arm64")
	}
	if GetGoArch(HdrArchUnknown) != "unknown" {
		t.Error(GetGoArch(HdrArchUnknown) != "unknown")
	}
}

func TestGetPartPrimSys(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			t.Errorf("Error unloading container: %v", err)
		}
	}()

	_, _, err = fimg.GetPartPrimSys()
	if err != nil {
		t.Error("fimg.GetPartPrimSys():", err)
	}
}
