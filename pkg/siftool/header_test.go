// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

//nolint:dupl
package siftool

import (
	"path/filepath"
	"testing"
)

func Test_command_getHeader(t *testing.T) {
	tests := []struct {
		name string
		opts commandOpts
		path string
	}{
		{
			name: "Empty",
			path: filepath.Join(corpus, "empty.sif"),
		},
		{
			name: "OneGroup",
			path: filepath.Join(corpus, "one-group.sif"),
		},
		{
			name: "OneGroupSigned",
			path: filepath.Join(corpus, "one-group-signed.sif"),
		},
		{
			name: "OneGroupSignedLegacy",
			path: filepath.Join(corpus, "one-group-signed-legacy.sif"),
		},
		{
			name: "OneGroupSignedLegacyAll",
			path: filepath.Join(corpus, "one-group-signed-legacy-all.sif"),
		},
		{
			name: "OneGroupSignedLegacyGroup",
			path: filepath.Join(corpus, "one-group-signed-legacy-group.sif"),
		},
		{
			name: "TwoGroups",
			path: filepath.Join(corpus, "two-groups.sif"),
		},
		{
			name: "TwoGroupsSigned",
			path: filepath.Join(corpus, "two-groups-signed.sif"),
		},
		{
			name: "TwoGroupsSignedLegacy",
			path: filepath.Join(corpus, "two-groups-signed-legacy.sif"),
		},
		{
			name: "TwoGroupsSignedLegacyAll",
			path: filepath.Join(corpus, "two-groups-signed-legacy-all.sif"),
		},
		{
			name: "TwoGroupsSignedLegacyGroup",
			path: filepath.Join(corpus, "two-groups-signed-legacy-group.sif"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &command{opts: tt.opts}

			cmd := c.getHeader()

			runCommand(t, cmd, []string{tt.path})
		})
	}
}
