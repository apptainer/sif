// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"testing"
)

func TestLoadContainer(t *testing.T) {
	_, err := LoadContainer("testdata/testcontainer.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer.sif, true):", err)
	}
}
