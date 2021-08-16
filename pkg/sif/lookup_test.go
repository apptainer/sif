// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"testing"
)

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
