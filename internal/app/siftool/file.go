// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"github.com/hpcng/sif/pkg/sif" //nolint:staticcheck // In use until v2 API
)

// withFileImage calls fn with a FileImage loaded from path.
func withFileImage(path string, writable bool, fn func(*sif.FileImage) error) (err error) {
	f, err := sif.LoadContainer(path, !writable)
	if err != nil {
		return err
	}
	defer func() {
		if uerr := f.UnloadContainer(); uerr != nil && err == nil {
			err = uerr
		}
	}()

	return fn(&f)
}
