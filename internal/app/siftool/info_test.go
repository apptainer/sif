// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/sebdah/goldie/v2"
)

var corpus = filepath.Join("..", "..", "..", "pkg", "integrity", "testdata", "images")

//nolint:dupl
func TestApp_Header(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{
			name: "Empty",
			path: filepath.Join(corpus, "empty.sif"),
		},
		{
			name: "OneGroup",
			path: filepath.Join(corpus, "one-group.sif"),
		},
		{
			name: "OneGroupSigned",
			path: filepath.Join(corpus, "one-group-signed.sif"),
		},
		{
			name: "OneGroupSignedLegacy",
			path: filepath.Join(corpus, "one-group-signed-legacy.sif"),
		},
		{
			name: "OneGroupSignedLegacyAll",
			path: filepath.Join(corpus, "one-group-signed-legacy-all.sif"),
		},
		{
			name: "OneGroupSignedLegacyGroup",
			path: filepath.Join(corpus, "one-group-signed-legacy-group.sif"),
		},
		{
			name: "TwoGroups",
			path: filepath.Join(corpus, "two-groups.sif"),
		},
		{
			name: "TwoGroupsSigned",
			path: filepath.Join(corpus, "two-groups-signed.sif"),
		},
		{
			name: "TwoGroupsSignedLegacy",
			path: filepath.Join(corpus, "two-groups-signed-legacy.sif"),
		},
		{
			name: "TwoGroupsSignedLegacyAll",
			path: filepath.Join(corpus, "two-groups-signed-legacy-all.sif"),
		},
		{
			name: "TwoGroupsSignedLegacyGroup",
			path: filepath.Join(corpus, "two-groups-signed-legacy-group.sif"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer

			a, err := New(OptAppOutput(&b))
			if err != nil {
				t.Fatalf("failed to create app: %v", err)
			}

			if got, want := a.Header(tt.path), tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}

//nolint:dupl
func TestApp_List(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{
			name: "Empty",
			path: filepath.Join(corpus, "empty.sif"),
		},
		{
			name: "OneGroup",
			path: filepath.Join(corpus, "one-group.sif"),
		},
		{
			name: "OneGroupSigned",
			path: filepath.Join(corpus, "one-group-signed.sif"),
		},
		{
			name: "OneGroupSignedLegacy",
			path: filepath.Join(corpus, "one-group-signed-legacy.sif"),
		},
		{
			name: "OneGroupSignedLegacyAll",
			path: filepath.Join(corpus, "one-group-signed-legacy-all.sif"),
		},
		{
			name: "OneGroupSignedLegacyGroup",
			path: filepath.Join(corpus, "one-group-signed-legacy-group.sif"),
		},
		{
			name: "TwoGroups",
			path: filepath.Join(corpus, "two-groups.sif"),
		},
		{
			name: "TwoGroupsSigned",
			path: filepath.Join(corpus, "two-groups-signed.sif"),
		},
		{
			name: "TwoGroupsSignedLegacy",
			path: filepath.Join(corpus, "two-groups-signed-legacy.sif"),
		},
		{
			name: "TwoGroupsSignedLegacyAll",
			path: filepath.Join(corpus, "two-groups-signed-legacy-all.sif"),
		},
		{
			name: "TwoGroupsSignedLegacyGroup",
			path: filepath.Join(corpus, "two-groups-signed-legacy-group.sif"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer

			a, err := New(OptAppOutput(&b))
			if err != nil {
				t.Fatalf("failed to create app: %v", err)
			}

			if got, want := a.List(tt.path), tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}

//nolint:dupl
func TestApp_Info(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		id      uint32
		wantErr error
	}{
		{
			name: "One",
			path: filepath.Join(corpus, "one-group-signed.sif"),
			id:   1,
		},
		{
			name: "Two",
			path: filepath.Join(corpus, "one-group-signed.sif"),
			id:   2,
		},
		{
			name: "Three",
			path: filepath.Join(corpus, "one-group-signed.sif"),
			id:   3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer

			a, err := New(OptAppOutput(&b))
			if err != nil {
				t.Fatalf("failed to create app: %v", err)
			}

			if got, want := a.Info(tt.path, tt.id), tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}

//nolint:dupl
func TestApp_Dump(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		id      uint32
		wantErr error
	}{
		{
			name: "One",
			path: filepath.Join(corpus, "one-group-signed.sif"),
			id:   1,
		},
		{
			name: "Two",
			path: filepath.Join(corpus, "one-group-signed.sif"),
			id:   2,
		},
		{
			name: "Three",
			path: filepath.Join(corpus, "one-group-signed.sif"),
			id:   3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer

			a, err := New(OptAppOutput(&b))
			if err != nil {
				t.Fatalf("failed to create app: %v", err)
			}

			if got, want := a.Dump(tt.path, tt.id), tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}
