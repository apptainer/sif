// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"io"
	"os"
)

// appOpts contains configured options.
type appOpts struct {
	out io.Writer
}

// AppOpt are used to configure optional behavior.
type AppOpt func(*appOpts) error

// App holds state and configured options.
type App struct {
	opts appOpts
}

// OptAppOutput specifies that output should be written to w.
func OptAppOutput(w io.Writer) AppOpt {
	return func(o *appOpts) error {
		o.out = w
		return nil
	}
}

// New creates a new App configured with opts.
func New(opts ...AppOpt) (*App, error) {
	a := App{
		opts: appOpts{
			out: os.Stdout,
		},
	}

	for _, opt := range opts {
		if err := opt(&a.opts); err != nil {
			return nil, err
		}
	}

	return &a, nil
}
