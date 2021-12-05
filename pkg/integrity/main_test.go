// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

var corpus = filepath.Join("..", "..", "test", "images")

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

	tf, err = os.CreateTemp("", pattern)
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

	f, err := os.Open(filepath.Join("..", "..", "test", "keys", "private.asc"))
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
