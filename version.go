// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// +build mage

package main

import (
	"errors"

	"github.com/blang/semver/v4"
)

// getVersion returns a semantic version based on d. If d is tagged directly, the parsed version is
// returned. Otherwise, a version is derived that preserves semantic precedence.
//
// For example:
//  - If d.tag.Name = "v0.1.2-alpha.1" and d.n = 1, 0.1.2-alpha.1.0.devel.1 is returned.
//  - If d.tag.Name = "v0.1.2" and d.n = 1, 0.1.3-0.devel.1 is returned.
//  - If d.tag.Name = "v0.1.3" and d.n = 0, 0.1.3 is returned.
func getVersion(d *gitDescription) (semver.Version, error) {
	if d.v == nil {
		return semver.Version{}, errors.New("no semver tags found")
	}

	// If this version wasn't tagged directly, modify tag.
	v := *d.v
	if d.n > 0 {
		if len(v.Pre) == 0 {
			v.Patch++
		}

		// Append "0.devel.N" pre-release components.
		v.Pre = append(v.Pre,
			semver.PRVersion{VersionNum: 0, IsNum: true},
			semver.PRVersion{VersionStr: "devel"},
			semver.PRVersion{VersionNum: d.n, IsNum: true},
		)
	}

	return v, nil
}
