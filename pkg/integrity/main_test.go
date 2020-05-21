// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update .golden files")

// goldenPath returns the path of the golden file corresponding to name.
func goldenPath(name string) string {
	// Replace test name separator with OS-specific path separator.
	name = path.Join(strings.Split(name, "/")...)
	return path.Join("testdata", name) + ".golden"
}

// updateGolden writes b to a golden file associated with name.
func updateGolden(name string, b []byte) error {
	p := goldenPath(name)
	if err := os.MkdirAll(path.Dir(p), 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(p, b, 0600)
}

// verifyGolden compares b to the contents golden file associated with name.
func verifyGolden(name string, r io.Reader) error {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	if *update {
		if err := updateGolden(name, b); err != nil {
			return err
		}
	}
	g, err := ioutil.ReadFile(goldenPath(name))
	if err != nil {
		return err
	}

	if !bytes.Equal(b, g) {
		return errors.New("output does not match golden file")
	}
	return nil
}

func TestMain(m *testing.M) {
	flag.Parse()

	os.Exit(m.Run())
}
