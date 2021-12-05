// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"testing"
)

func TestGetSIFArch(t *testing.T) {
	tests := []struct {
		name     string
		arch     string
		wantArch archType
	}{
		{
			name:     "386",
			arch:     "386",
			wantArch: hdrArch386,
		},
		{
			name:     "ARM64",
			arch:     "arm64",
			wantArch: hdrArchARM64,
		},
		{
			name:     "Unknown",
			arch:     "cray",
			wantArch: hdrArchUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := getSIFArch(tt.arch), tt.wantArch; got != want {
				t.Errorf("got arch %v, want %v", got, want)
			}
		})
	}
}

func TestArchType_GetGoArch(t *testing.T) {
	tests := []struct {
		name     string
		arch     archType
		wantArch string
	}{
		{
			name:     "386",
			arch:     hdrArch386,
			wantArch: "386",
		},
		{
			name:     "ARM64",
			arch:     hdrArchARM64,
			wantArch: "arm64",
		},
		{
			name:     "Unknown",
			arch:     hdrArchUnknown,
			wantArch: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := tt.arch.GoArch(), tt.wantArch; got != want {
				t.Errorf("got arch %v, want %v", got, want)
			}
		})
	}
}
