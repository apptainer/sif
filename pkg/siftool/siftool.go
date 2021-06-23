// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// Package siftool adds siftool commands to a parent cobra.Command.
package siftool

import (
	"github.com/spf13/cobra"
	"github.com/sylabs/sif/v2/internal/app/siftool"
)

// commandOpts contains configured options.
type commandOpts struct {
	app *siftool.App
}

// CommandOpt are used to configure optional command behavior.
type CommandOpt func(*commandOpts) error

// AddCommands adds siftool commands to cmd according to opts.
//
// A set of commands are provided to display elements such as the SIF global
// header, the data object descriptors and to dump data objects. It is also
// possible to modify a SIF file via this tool via the add/del commands.
func AddCommands(cmd *cobra.Command, opts ...CommandOpt) error {
	app, err := siftool.New()
	if err != nil {
		return err
	}

	co := commandOpts{app: app}

	for _, opt := range opts {
		if err := opt(&co); err != nil {
			return err
		}
	}

	cmd.AddCommand(
		getHeader(co),
		getList(co),
		getInfo(co),
		getDump(co),
		getNew(co),
		getAdd(co),
		getDel(co),
		getSetPrim(co),
	)

	return nil
}
