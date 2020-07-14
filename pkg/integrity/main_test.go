// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/openpgp"
)

var update = flag.Bool("update", false, "update .golden files")

// fixedTime returns a fixed time value, useful for ensuring tests are deterministic.
func fixedTime() time.Time {
	return time.Unix(1504657553, 0)
}

// tempFileFrom copies the file at path to a temporary file, and returns a reference to it.
func tempFileFrom(path string) (tf *os.File, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	pattern := "*"
	if ext := filepath.Ext(path); ext != "" {
		pattern = fmt.Sprintf("*.%s", ext)
	}

	tf, err = ioutil.TempFile("", pattern)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			tf.Close()
		}
	}()

	if _, err := io.Copy(tf, f); err != nil {
		return nil, err
	}

	if _, err := tf.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	return tf, nil
}

// getTestEntity returns a fixed test PGP entity.
func getTestEntity(t *testing.T) *openpgp.Entity {
	t.Helper()

	f, err := os.Open(filepath.Join("testdata", "keys", "private.asc"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	el, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(el), 1; got != want {
		t.Fatalf("got %v entities, want %v", got, want)
	}
	return el[0]
}

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
	return ioutil.WriteFile(p, b, 0644) // nolint:gosec
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
