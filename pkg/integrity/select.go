// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"errors"

	"github.com/sylabs/sif/pkg/sif"
)

var (
	errInvalidObjectID      = errors.New("invalid object ID")
	errInvalidGroupID       = errors.New("invalid group ID")
	errMultipleObjectsFound = errors.New("multiple objects found")
	errObjectNotFound       = errors.New("object not found")
	errGroupNotFound        = errors.New("group not found")
)

// getObject returns the descriptor in f associated with the object with identifier id. If multiple
// such objects are found, errMultipleObjectsFound is returned. If no such object is found,
// errObjectNotFound is returned.
func getObject(f *sif.FileImage, id uint32) (*sif.Descriptor, error) {
	if id == 0 {
		return nil, errInvalidObjectID
	}

	od, _, err := f.GetFromDescrID(id)
	switch {
	case errors.Is(err, sif.ErrMultValues):
		err = errMultipleObjectsFound
	case errors.Is(err, sif.ErrNotFound):
		err = errObjectNotFound
	}
	return od, err
}

// getGroupObjects returns all descriptors in f that are contained in the object group with
// identifier groupID. If no such object group is found, errGroupNotFound is returned.
func getGroupObjects(f *sif.FileImage, groupID uint32) ([]*sif.Descriptor, error) {
	if groupID == 0 {
		return nil, errInvalidGroupID
	}

	ods, _, err := f.GetFromDescr(sif.Descriptor{
		Groupid: groupID | sif.DescrGroupMask,
	})
	if errors.Is(err, sif.ErrNotFound) {
		err = errGroupNotFound
	}
	return ods, err
}
