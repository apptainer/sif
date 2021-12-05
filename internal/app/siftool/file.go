// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"os"

	"github.com/apptainer/sif/v2/pkg/sif"
)

// withFileImage calls fn with a FileImage loaded from path.
func withFileImage(path string, writable bool, fn func(*sif.FileImage) error) (err error) {
	flag := os.O_RDONLY
	if writable {
		flag = os.O_RDWR
	}

	f, err := sif.LoadContainerFromPath(path, sif.OptLoadWithFlag(flag))
	if err != nil {
		return err
	}
	defer func() {
		if uerr := f.UnloadContainer(); uerr != nil && err == nil {
			err = uerr
		}
	}()

	return fn(f)
}
