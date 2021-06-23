// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"os"
	"testing"
)

func TestApp_New(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	tf, err := os.CreateTemp("", "sif-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	tf.Close()

	if err := a.New(tf.Name()); err != nil {
		t.Fatal(err)
	}
}
