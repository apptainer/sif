// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

// appOpts contains configured options.
type appOpts struct{}

// AppOpt are used to configure optional behavior.
type AppOpt func(*appOpts) error

// App holds state and configured options.
type App struct {
	opts appOpts
}

// New creates a new App configured with opts.
func New(opts ...AppOpt) (*App, error) {
	a := App{}

	for _, opt := range opts {
		if err := opt(&a.opts); err != nil {
			return nil, err
		}
	}

	return &a, nil
}
