// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"testing"

	"github.com/sebdah/goldie/v2"
)

func TestFileImage_FmtHeader(t *testing.T) {
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Fatalf(`Could not load test container: %v`, err)
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			t.Errorf("Error unloading container: %v", err)
		}
	}()

	actual := fimg.FmtHeader()

	g := goldie.New(t, goldie.WithTestNameForDir(true))
	g.Assert(t, "output", []byte(actual))
}

func TestFileImage_FmtDescrList(t *testing.T) {
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Fatalf(`Could not load test container: %v`, err)
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			t.Errorf("Error unloading container: %v", err)
		}
	}()

	actual := fimg.FmtDescrList()

	g := goldie.New(t, goldie.WithTestNameForDir(true))
	g.Assert(t, "output", []byte(actual))
}

func TestFileImage_FmtDescrInfo(t *testing.T) {
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Fatalf(`Could not load test container: %v`, err)
	}
	defer func() {
		if err := fimg.UnloadContainer(); err != nil {
			t.Errorf("Error unloading container: %v", err)
		}
	}()

	tests := []struct {
		name string
		id   uint32
	}{
		{
			name: "One",
			id:   1,
		},
		{
			name: "Two",
			id:   2,
		},
		{
			name: "Three",
			id:   3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := fimg.FmtDescrInfo(tt.id)

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, []byte(actual))
		})
	}
}
