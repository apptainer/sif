// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
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

func TestFromDescr(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	// Simple lookup of a descriptor of type Deffile (present)
	descr := Descriptor{
		Datatype: DataDeffile,
	}
	_, _, err = fimg.GetFromDescr(descr)
	if err != nil {
		t.Error("fimg.GetFromDescr(descr): should have found descriptor:", err)
	}

	// Simple lookup of a descriptor of type EnvVar (non-existent)
	descr = Descriptor{
		Datatype: DataEnvVar,
	}
	_, _, err = fimg.GetFromDescr(descr)
	if err == nil {
		t.Error("fimg.GetFromDescr(descr): should not have found descriptor:", err)
	}

	// Example with very pinpointed descriptor lookup
	descr = Descriptor{
		Datatype: DataPartition,
		ID:       2,
		Groupid:  DescrDefaultGroup,
		Link:     DescrUnusedLink,
		UID:      1002,
		Gid:      1002,
	}
	descr.SetName("busybox.squash")
	_, _, err = fimg.GetFromDescr(descr)
	if err != nil {
		t.Error("fimg.GetFromDescr(descr): should have found descriptor:", err)
	}

	// Same example but with the field "Name" spelled wrong (busyb0x)
	descr = Descriptor{
		Datatype: DataPartition,
		ID:       2,
		Groupid:  DescrDefaultGroup,
		Link:     DescrUnusedLink,
		UID:      1002,
		Gid:      1002,
	}
	descr.SetName("busyb0x.squash")
	_, _, err = fimg.GetFromDescr(descr)
	if err == nil {
		t.Error("fimg.GetFromDescr(descr): should have not found descriptor:", err)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestGetData(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}
	defer fimg.UnloadContainer()

	// Get the signature block
	descr, _, err := fimg.GetFromDescrID(3)
	if err != nil {
		t.Error("fimg.GetFromDescrID(): should have found descriptor")
	}

	data := descr.GetData(&fimg)

	if string(data[5:10]) != "BEGIN" {
		t.Errorf("expected `BEGIN' at data[5:9], got `%s'", data[5:10])
	}
}

func TestGetName(t *testing.T) {
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

	if parts[0].GetName() != "busybox.squash" {
		t.Error(`parts[0].GetName() != "busybox.squash"`)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestGetFsType(t *testing.T) {
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

	fstype, err := parts[0].GetFsType()
	if err != nil {
		t.Error("parts[0].GetFsType()", err)
	}

	if fstype != FsSquash {
		t.Error("part.GetFsType() should have returned 'FsSquash'")
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestGetPartType(t *testing.T) {
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

	parttype, err := parts[0].GetPartType()
	if err != nil {
		t.Error("parts[0].GetPartType()", err)
	}

	if parttype != PartPrimSys {
		t.Error("part.GetPartType() should have returned 'PartPrimSys'")
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestGetArch(t *testing.T) {
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

	arch, err := parts[0].GetArch()
	if err != nil {
		t.Error("parts[0].GetArch()", err)
	}

	if string(arch[:HdrArchLen-1]) != HdrArchAMD64 {
		t.Logf("|%s|%s|\n", arch[:HdrArchLen-1], HdrArchAMD64)
		t.Error("part.GetArch() should have returned 'HdrArchAMD64':", err)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestGetHashType(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	sigs, _, err := fimg.GetSignFromGroup(DescrDefaultGroup)
	if err != nil {
		t.Error("fimg.GetSignFromGroup(DescrDefaultGroup): should have found descriptor:", err)
	}

	if len(sigs) != 1 {
		t.Error("multiple signatures found where expecting 1")
	}

	hashtype, err := sigs[0].GetHashType()
	if err != nil {
		t.Error("sigs[0].GetHashType()", err)
	}

	if hashtype != HashSHA384 {
		t.Error("sig.GetHashType() should have returned 'HashSHA384'")
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestGetEntity(t *testing.T) {
	expected := []byte{159, 43, 108, 54, 217, 153, 163, 233, 28, 179, 16, 71, 32, 103, 21, 144, 193, 45, 66, 34}

	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	sigs, _, err := fimg.GetSignFromGroup(DescrDefaultGroup)
	if err != nil {
		t.Error("fimg.GetSignFromGroup(DescrDefaultGroup): should have found descriptor:", err)
	}

	if len(sigs) != 1 {
		t.Error("multiple signatures found where expecting 1")
	}

	entity, err := sigs[0].GetEntity()
	if err != nil {
		t.Error("sigs[0].GetEntity()", err)
	}

	if bytes.Equal(expected, entity[:len(expected)]) == false {
		t.Error("sig.GetEntity(): didn't get the expected entity, got:", entity[:len(expected)])
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestGetEntityString(t *testing.T) {
	expected := "9F2B6C36D999A3E91CB3104720671590C12D4222"

	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	sigs, _, err := fimg.GetSignFromGroup(DescrDefaultGroup)
	if err != nil {
		t.Error("fimg.GetSignFromGroup(DescrDefaultGroup): should have found descriptor:", err)
	}

	if len(sigs) != 1 {
		t.Error("multiple signatures found where expecting 1")
	}

	entity, err := sigs[0].GetEntityString()
	if err != nil {
		t.Error("sigs[0].GetEntityString()", err)
	}

	if expected != entity {
		t.Error("sig.GetEntityString(): didn't get the expected entity")
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
	fimg.UnloadContainer()

	_, _, err = fimg.GetPartPrimSys()
	if err != nil {
		t.Error("fimg.GetPartPrimSys():", err)
	}
}
