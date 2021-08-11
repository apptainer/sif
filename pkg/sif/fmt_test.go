// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"testing"

	"github.com/sebdah/goldie/v2"
)

func Test_readableSize(t *testing.T) {
	tests := []struct {
		name string
		size uint64
		want string
	}{
		{
			name: "B",
			size: 1,
			want: "1 B",
		},
		{
			name: "KiB",
			size: 1024,
			want: "1 KiB",
		},
		{
			name: "MiB",
			size: 1024 * 1024,
			want: "1 MiB",
		},
		{
			name: "GiB",
			size: 1024 * 1024 * 1024,
			want: "1 GiB",
		},
		{
			name: "TiB",
			size: 1024 * 1024 * 1024 * 1024,
			want: "1 TiB",
		},
		{
			name: "PiB",
			size: 1024 * 1024 * 1024 * 1024 * 1024,
			want: "1 PiB",
		},
		{
			name: "EiB",
			size: 1024 * 1024 * 1024 * 1024 * 1024 * 1024,
			want: "1 EiB",
		},
		{
			name: "Rounding",
			size: 2047,
			want: "2 KiB",
		},
	}
	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			if got, want := readableSize(tt.size), tt.want; got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

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
