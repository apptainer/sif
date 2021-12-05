// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// Package siftool adds siftool commands to a parent cobra.Command.
package siftool

import (
	"github.com/apptainer/sif/v2/internal/app/siftool"
	"github.com/spf13/cobra"
)

// command contains options and command state.
type command struct {
	opts commandOpts
	app  *siftool.App
}

// initApp initializes the siftool app.
func (c *command) initApp(cmd *cobra.Command, args []string) error {
	app, err := siftool.New(
		siftool.OptAppOutput(cmd.OutOrStdout()),
	)
	c.app = app

	return err
}

// commandOpts contains configured options.
type commandOpts struct {
	rootPath string
}

// CommandOpt are used to configure optional command behavior.
type CommandOpt func(*commandOpts) error

// AddCommands adds siftool commands to cmd according to opts.
//
// A set of commands are provided to display elements such as the SIF global
// header, the data object descriptors and to dump data objects. It is also
// possible to modify a SIF file via this tool via the add/del commands.
func AddCommands(cmd *cobra.Command, opts ...CommandOpt) error {
	c := command{
		opts: commandOpts{
			rootPath: cmd.CommandPath(),
		},
	}

	for _, opt := range opts {
		if err := opt(&c.opts); err != nil {
			return err
		}
	}

	cmd.AddCommand(
		c.getHeader(),
		c.getList(),
		c.getInfo(),
		c.getDump(),
		c.getNew(),
		c.getAdd(),
		c.getDel(),
		c.getSetPrim(),
	)

	return nil
}
