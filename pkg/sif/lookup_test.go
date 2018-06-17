// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"testing"
)

func TestGetHeader(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
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

func TestGetFromDescrID(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	_, _, err = fimg.GetFromDescrID("da4ef1f5")
	if err != nil {
		t.Error("fimg.GetFromDescrID(): should have found descriptor")
	}

	_, _, err = fimg.GetFromDescrID("da")
	if err != nil {
		t.Error("fimg.GetFromDescrID(): should have found descriptor")
	}

	_, _, err = fimg.GetFromDescrID("abc02448-6d9b-4918-b72c-e2fea09fac43")
	if err != nil {
		t.Error("fimg.GetFromDescrID(): should have found descriptor")
	}

	_, _, err = fimg.GetFromDescrID("bc02448-6d9b-4918-b72c-e2fea09fac43")
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

func SkipTestGetSignFromGroup(t *testing.T) {
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
