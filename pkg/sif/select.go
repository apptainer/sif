// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import "errors"

// DescriptorSelectorFunc returns true if d matches, and false otherwise.
type DescriptorSelectorFunc func(d Descriptor) (bool, error)

// withDescriptors calls onMatchFn with each in-use descriptor in f for which selectFn returns
// true. If selectFn or onMatchFn return a non-nil error, the iteration halts, and the error is
// returned to the caller.
func (f *FileImage) withDescriptors(selectFn DescriptorSelectorFunc, onMatchFn func(*Descriptor) error) error {
	for i, d := range f.descrArr {
		if !d.Used {
			continue
		}

		if ok, err := selectFn(f.descrArr[i]); err != nil {
			return err
		} else if !ok {
			continue
		}

		if err := onMatchFn(&f.descrArr[i]); err != nil {
			return err
		}
	}

	return nil
}

// abortOnMatch is a semantic convenience function that always returns a non-nil error, which can
// be used as a no-op matchFn.
func abortOnMatch(*Descriptor) error { return errors.New("") }

// WithDescriptors calls fn with each in-use descriptor in f, until fn returns true.
func (f *FileImage) WithDescriptors(fn func(d Descriptor) bool) {
	selectFn := func(d Descriptor) (bool, error) {
		return fn(d), nil
	}
	_ = f.withDescriptors(selectFn, abortOnMatch)
}
