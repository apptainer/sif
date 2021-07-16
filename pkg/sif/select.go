// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"errors"
	"fmt"
)

// ErrObjectNotFound is the error returned when a data object is not found.
var ErrObjectNotFound = errors.New("object not found")

// ErrMultipleObjectsFound is the error returned when multiple data objects are found.
var ErrMultipleObjectsFound = errors.New("multiple objects found")

var (
	errInvalidObjectID = errors.New("invalid object ID")
	errInvalidGroupID  = errors.New("invalid group ID")
)

// DescriptorSelectorFunc returns true if d matches, and false otherwise.
type DescriptorSelectorFunc func(d Descriptor) (bool, error)

// WithDataType selects descriptors that have data type dt.
func WithDataType(dt Datatype) DescriptorSelectorFunc {
	return func(d Descriptor) (bool, error) {
		return d.GetDataType() == dt, nil
	}
}

// WithID selects descriptors with a matching ID.
func WithID(id uint32) DescriptorSelectorFunc {
	return func(d Descriptor) (bool, error) {
		if id == 0 {
			return false, errInvalidObjectID
		}
		return d.GetID() == id, nil
	}
}

// WithNoGroup selects descriptors that are not contained within an object group.
func WithNoGroup() DescriptorSelectorFunc {
	return func(d Descriptor) (bool, error) {
		return d.GetGroupID() == 0, nil
	}
}

// WithGroupID returns a selector func that selects descriptors with a matching groupID.
func WithGroupID(groupID uint32) DescriptorSelectorFunc {
	return func(d Descriptor) (bool, error) {
		if groupID == 0 {
			return false, errInvalidGroupID
		}
		return d.GetGroupID() == groupID, nil
	}
}

// WithLinkedID selects descriptors that are linked to the data object with specified ID.
func WithLinkedID(id uint32) DescriptorSelectorFunc {
	return func(d Descriptor) (bool, error) {
		if id == 0 {
			return false, errInvalidObjectID
		}
		linkedID, isGroup := d.GetLinkedID()
		return !isGroup && linkedID == id, nil
	}
}

// WithLinkedGroupID selects descriptors that are linked to the data object group with specified
// ID.
func WithLinkedGroupID(groupID uint32) DescriptorSelectorFunc {
	return func(d Descriptor) (bool, error) {
		if groupID == 0 {
			return false, errInvalidGroupID
		}
		linkedID, isGroup := d.GetLinkedID()
		return isGroup && linkedID == groupID, nil
	}
}

// GetDescriptors returns a slice of in-use descriptors for which all selector funcs return true.
func (f *FileImage) GetDescriptors(fns ...DescriptorSelectorFunc) ([]Descriptor, error) {
	var ds []Descriptor

	err := f.withDescriptors(multiSelectorFunc(fns...), func(d *Descriptor) error {
		ds = append(ds, *d)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return ds, nil
}

// getDescriptor returns a pointer to the in-use descriptor selected by fns. If no descriptor is
// selected by fns, ErrObjectNotFound is returned. If multiple descriptors are selected by fns,
// ErrMultipleObjectsFound is returned.
func (f *FileImage) getDescriptor(fns ...DescriptorSelectorFunc) (*Descriptor, error) {
	var d *Descriptor

	err := f.withDescriptors(multiSelectorFunc(fns...), func(found *Descriptor) error {
		if d != nil {
			return ErrMultipleObjectsFound
		}
		d = found
		return nil
	})

	if err == nil && d == nil {
		err = ErrObjectNotFound
	}

	return d, err
}

// GetDescriptor returns the in-use descriptor selected by fns. If no descriptor is selected by
// fns, an error wrapping ErrObjectNotFound is returned. If multiple descriptors are selected by
// fns, an error wrapping ErrMultipleObjectsFound is returned.
func (f *FileImage) GetDescriptor(fns ...DescriptorSelectorFunc) (Descriptor, error) {
	d, err := f.getDescriptor(fns...)
	if err != nil {
		return Descriptor{}, fmt.Errorf("%w", err)
	}
	return *d, nil
}

// multiSelectorFunc returns a DescriptorSelectorFunc that selects a descriptor iff all of fns
// select the descriptor.
func multiSelectorFunc(fns ...DescriptorSelectorFunc) DescriptorSelectorFunc {
	return func(d Descriptor) (bool, error) {
		for _, fn := range fns {
			if ok, err := fn(d); !ok || err != nil {
				return ok, err
			}
		}
		return true, nil
	}
}

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
