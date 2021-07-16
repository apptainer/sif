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

func TestGetPartFromGroup(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	_, _, err = fimg.GetPartFromGroup(DescrDefaultGroup)
	if err != nil {
		t.Error("fimg.GetPartFromGroup(DescrDefaultGroup): should have found descriptor:", err)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestGetSignFromGroup(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	_, _, err = fimg.GetSignFromGroup(DescrDefaultGroup)
	if err != nil {
		t.Error("fimg.GetSignFromGroup(DescrDefaultGroup): should have found descriptor:", err)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestGetLinkedDescrsByType(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	parts, _, err := fimg.GetPartFromGroup(DescrDefaultGroup)
	if err != nil {
		t.Error("fimg.GetPartFromGroup(DescrDefaultGroup): should have found descriptor:", err)
	}

	if len(parts) != 1 {
		t.Error("multiple partitions found where expecting 1")
	}

	fd, snum, err := fimg.GetLinkedDescrsByType(parts[0].ID, DataSignature)
	if err != nil {
		t.Error("fimg.GetLinkedDescrsByType(parts[0].ID): should have found descriptor:", err)
	}

	if len(snum) != 1 {
		t.Error("multiple signature partitions found, was expecting 1")
	}
	if len(fd) != 1 {
		t.Error("multiple signature partitions found, was expecting 1")
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}

	//
	// Test with a container without a signature partition
	//

	// load the test container
	fimg, err = LoadContainer("testdata/testcontainer1.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer1.sif, true):", err)
	}

	fd, snum, err = fimg.GetLinkedDescrsByType(parts[0].ID, DataSignature)
	if err == nil {
		t.Error("fimg.GetLinkedDescrsByType(parts[0].ID): unexpected signature partition: ", err)
	}

	if len(snum) != 0 {
		t.Error("unexpected signature partition(s) found, was expecting 0")
	}
	if len(fd) != 0 {
		t.Error("unexpected signature partition(s) found, was expecting 0")
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestGetFromLinkedDescr(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	parts, _, err := fimg.GetPartFromGroup(DescrDefaultGroup)
	if err != nil {
		t.Error("fimg.GetPartFromGroup(DescrDefaultGroup): should have found descriptor:", err)
	}

	if len(parts) != 1 {
		t.Error("multiple partitions found where expecting 1")
	}

	_, _, err = fimg.GetFromLinkedDescr(parts[0].ID)
	if err != nil {
		t.Error("fimg.GetFromLinkedDescr(parts[0].ID): should have found descriptor:", err)
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
