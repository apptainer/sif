// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"testing"
)

func TestFileImage_FmtHeader(t *testing.T) {
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Fatalf(`Could not load test container: %v`, err)
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			t.Errorf("Error unloading container: %v", err)
		}
	}()

	const expectHeader = `Launch:   #!/usr/bin/env run-singularity

Magic:    SIF_MAGIC
Version:  00
Arch:     amd64
ID:       293e8b11-dbd0-47e6-b0b9-390772c12be8
Ctime:    2018-08-14 07:45:59 +0000 UTC
Mtime:    2018-08-14 07:47:36 +0000 UTC
Dfree:    45
Dtotal:   48
Descoff:  4096
Descrlen: 27KB
Dataoff:  32768
Datalen:  1MB
`

	actual := fimg.FmtHeader()
	if expectHeader != actual {
		t.Errorf("Expected header:\n%q\nBut got:\n%q", expectHeader, actual)
	}
}

func TestFileImage_FmtDescrList(t *testing.T) {
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Fatalf(`Could not load test container: %v`, err)
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			t.Errorf("Error unloading container: %v", err)
		}
	}()

	const expectList = `ID   |GROUP   |LINK    |SIF POSITION (start-end)  |TYPE
------------------------------------------------------------------------------
1    |1       |NONE    |32768-32830               |Def.FILE
2    |1       |NONE    |1048576-1753088           |FS (Squashfs/*System/amd64)
3    |1       |2       |1753088-1754043           |Signature (SHA384)
`

	actual := fimg.FmtDescrList()
	if expectList != actual {
		t.Errorf("Expected list:\n%q\nBut got:\n%q", expectList, actual)
	}
}

func TestFileImage_FmtDescrInfo(t *testing.T) {
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Fatalf(`Could not load test container: %v`, err)
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			t.Errorf("Error unloading container: %v", err)
		}
	}()

	expect := []string{
		`Descr slot#: 0
  Datatype:  Def.FILE
  ID:        1
  Used:      true
  Groupid:   1
  Link:      NONE
  Fileoff:   32768
  Filelen:   62
  Ctime:     2018-08-14 07:45:59 +0000 UTC
  Mtime:     2018-08-14 07:45:59 +0000 UTC
  UID:       1002
  Gid:       1002
  Name:      busybox.deffile
`,
		`Descr slot#: 1
  Datatype:  FS
  ID:        2
  Used:      true
  Groupid:   1
  Link:      NONE
  Fileoff:   1048576
  Filelen:   704512
  Ctime:     2018-08-14 07:45:59 +0000 UTC
  Mtime:     2018-08-14 07:45:59 +0000 UTC
  UID:       1002
  Gid:       1002
  Name:      busybox.squash
  Fstype:    Squashfs
  Parttype:  *System
  Arch:      amd64
`,
		`Descr slot#: 2
  Datatype:  Signature
  ID:        3
  Used:      true
  Groupid:   1
  Link:      2
  Fileoff:   1753088
  Filelen:   955
  Ctime:     2018-08-14 07:47:36 +0000 UTC
  Mtime:     2018-08-14 07:47:36 +0000 UTC
  UID:       1002
  Gid:       1002
  Name:      part-signature
  Hashtype:  SHA384
  Entity:    9F2B6C36D999A3E91CB3104720671590C12D4222
`,
		``,
	}

	for i := 0; i < len(expect); i++ {
		actual := fimg.FmtDescrInfo(uint32(i + 1))
		if len(expect[i]) != len(actual) {
			t.Errorf("Expected info len: %d, but got: %d", len(expect[i]), len(actual))

		}
		if expect[i] != actual {
			t.Errorf("Expected info:\n%q\nBut got:\n%q", expect[i], actual)
		}
	}
}
