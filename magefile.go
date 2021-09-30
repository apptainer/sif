// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

//go:build mage
// +build mage

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hpcng/sif/v2/internal/pkg/git"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Aliases defines command-line aliases exposed by Mage.
//nolint:deadcode
var Aliases = map[string]interface{}{
	"build":   Build.All,
	"cover":   Cover.All,
	"install": Install.All,
	"test":    Test.All,
}

// env returns the environment to use when running Go commands.
func env() map[string]string {
	return map[string]string{"CGO_ENABLED": "0"}
}

// ldFlags returns linker flags to pass to various Go commands.
func ldFlags() string {
	vals := []string{"-s", "-w", "-X", "main.builtBy=mage"}

	// Attempt to get git details.
	if d, err := git.Describe("."); err == nil {
		vals = append(vals, "-X", fmt.Sprintf("main.commit=%v", d.CommitHash()))

		if d.IsClean() {
			vals = append(vals,
				"-X", fmt.Sprintf("main.date=%v", d.CommitTime().UTC().Format(time.RFC3339)),
				"-X", "main.state=clean",
			)
		} else {
			vals = append(vals,
				"-X", fmt.Sprintf("main.date=%v", time.Now().UTC().Format(time.RFC3339)),
				"-X", "main.state=dirty",
			)
		}

		if v, err := d.Version(); err == nil {
			vals = append(vals, "-X", fmt.Sprintf("main.version=%v", v))
		} else {
			fmt.Fprintf(os.Stderr, "warning: failed to get version: %v\n", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "warning: failed to describe git HEAD: %v\n", err)

		vals = append(vals, "-X", fmt.Sprintf("main.date=%v", time.Now().UTC().Format(time.RFC3339)))
	}

	return strings.Join(vals, " ")
}

type Build mg.Namespace

// All compiles all assets.
func (ns Build) All() {
	mg.Deps(ns.Source)
}

// Source compiles all source code.
func (Build) Source() error {
	return sh.RunWith(env(), mg.GoCmd(), "build", "-trimpath", "-ldflags", ldFlags(), "./...")
}

type Install mg.Namespace

// All installs all assets.
func (ns Install) All() {
	mg.Deps(ns.Bin)
}

// Bin installs binary to GOBIN.
func (Install) Bin() error {
	return sh.RunWith(env(), mg.GoCmd(), "install", "-trimpath", "-ldflags", ldFlags(), "./cmd/siftool")
}

type Test mg.Namespace

// All runs all tests.
func (ns Test) All() {
	mg.Deps(ns.Unit)
}

// Unit runs all unit tests.
func (Test) Unit() error {
	return sh.RunV(mg.GoCmd(), "test", "-race", "-cover", "./...")
}

type Cover mg.Namespace

// All runs all tests, writing coverage profile to the specified path.
func (ns Cover) All(path string) {
	mg.Deps(mg.F(ns.Unit, path))
}

// Unit runs all unit tests, writing coverage profile to the specified path.
func (Cover) Unit(path string) error {
	return sh.RunV(mg.GoCmd(), "test", "-race", "-coverprofile", path, "./...")
}
