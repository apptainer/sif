// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

//go:build mage
// +build mage

package main

import (
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/sylabs/release-tools/pkg/cmd"
	"github.com/sylabs/release-tools/pkg/git"
)

// Aliases defines command-line aliases exposed by Mage.
//nolint:deadcode
var Aliases = map[string]interface{}{
	"build":   Build.All,
	"cover":   Cover.All,
	"install": Install.All,
	"test":    Test.All,
}

type Build mg.Namespace

// All compiles all assets.
func (ns Build) All() {
	mg.Deps(ns.Source)
}

// Source compiles all source code.
func (Build) Source() error {
	d, err := git.Describe(".")
	if err != nil {
		return err
	}

	c, err := cmd.NewBuildCommand(
		cmd.OptBuildWithBuiltBy("mage"),
		cmd.OptBuildWithGitDescription(d),
	)
	if err != nil {
		return err
	}

	return sh.RunWith(c.Env(), mg.GoCmd(), c.Args()...)
}

type Install mg.Namespace

// All installs all assets.
func (ns Install) All() {
	mg.Deps(ns.Bin)
}

// Bin installs binary to GOBIN.
func (Install) Bin() error {
	d, err := git.Describe(".")
	if err != nil {
		return err
	}

	c, err := cmd.NewInstallCommand(
		cmd.OptBuildPackages("./cmd/siftool"),
		cmd.OptBuildWithBuiltBy("mage"),
		cmd.OptBuildWithGitDescription(d),
	)
	if err != nil {
		return err
	}

	return sh.RunWith(c.Env(), mg.GoCmd(), c.Args()...)
}

type Test mg.Namespace

// All runs all tests.
func (ns Test) All() {
	mg.Deps(ns.Unit)
}

// Unit runs all unit tests.
func (Test) Unit() error {
	c, err := cmd.NewTestCommand()
	if err != nil {
		return err
	}

	return sh.RunWith(c.Env(), mg.GoCmd(), c.Args()...)
}

type Cover mg.Namespace

// All runs all tests, writing coverage profile to the specified path.
func (ns Cover) All(path string) {
	mg.Deps(mg.F(ns.Unit, path))
}

// Unit runs all unit tests, writing coverage profile to the specified path.
func (Cover) Unit(path string) error {
	c, err := cmd.NewTestCommand(
		cmd.OptTestWithCoverPath(path),
	)
	if err != nil {
		return err
	}

	return sh.RunWith(c.Env(), mg.GoCmd(), c.Args()...)
}
