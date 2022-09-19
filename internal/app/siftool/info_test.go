// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/apptainer/sif/v2/pkg/sif"
	"github.com/sebdah/goldie/v2"
)

var corpus = filepath.Join("..", "..", "..", "test", "images")

func Test_readableSize(t *testing.T) {
	tests := []struct {
		name string
		size int64
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

//nolint:dupl
func TestApp_Header(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{
			name:    "NotExist",
			path:    "not-exist.sif",
			wantErr: os.ErrNotExist,
		},
		{
			name: "Empty",
			path: filepath.Join(corpus, "empty.sif"),
		},
		{
			name: "EmptyID",
			path: filepath.Join(corpus, "empty-id.sif"),
		},
		{
			name: "EmptyLaunchScript",
			path: filepath.Join(corpus, "empty-launch-script.sif"),
		},
		{
			name: "OneObjectTime",
			path: filepath.Join(corpus, "one-object-time.sif"),
		},
		{
			name: "OneObjectGenericJSON",
			path: filepath.Join(corpus, "one-object-generic-json.sif"),
		},
		{
			name: "OneObjectCryptMessage",
			path: filepath.Join(corpus, "one-object-crypt-message.sif"),
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
			name: "OneGroupSignedX509",
			path: filepath.Join(corpus, "one-group-signed-x509.sif"),
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
			name: "TwoGroupsSignedX509",
			path: filepath.Join(corpus, "two-groups-signed-x509.sif"),
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

			if tt.wantErr == nil {
				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
			}
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
			name:    "NotExist",
			path:    "not-exist.sif",
			wantErr: os.ErrNotExist,
		},
		{
			name: "Empty",
			path: filepath.Join(corpus, "empty.sif"),
		},
		{
			name: "EmptyID",
			path: filepath.Join(corpus, "empty-id.sif"),
		},
		{
			name: "EmptyLaunchScript",
			path: filepath.Join(corpus, "empty-launch-script.sif"),
		},
		{
			name: "OneObjectTime",
			path: filepath.Join(corpus, "one-object-time.sif"),
		},
		{
			name: "OneObjectGenericJSON",
			path: filepath.Join(corpus, "one-object-generic-json.sif"),
		},
		{
			name: "OneObjectCryptMessage",
			path: filepath.Join(corpus, "one-object-crypt-message.sif"),
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
			name: "OneGroupSignedX509",
			path: filepath.Join(corpus, "one-group-signed-x509.sif"),
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
			name: "TwoGroupsSignedX509",
			path: filepath.Join(corpus, "two-groups-signed-x509.sif"),
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

			if tt.wantErr == nil {
				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
			}
		})
	}
}

func TestApp_Info(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		id      uint32
		wantErr error
	}{
		{
			name:    "NotExist",
			path:    "not-exist.sif",
			wantErr: os.ErrNotExist,
		},
		{
			name: "Time",
			path: filepath.Join(corpus, "one-object-time.sif"),
			id:   1,
		},
		{
			name: "GenericJSON",
			path: filepath.Join(corpus, "one-object-generic-json.sif"),
			id:   1,
		},
		{
			name: "CryptMessage",
			path: filepath.Join(corpus, "one-object-crypt-message.sif"),
			id:   1,
		},
		{
			name: "DataPartitionRaw",
			path: filepath.Join(corpus, "two-groups-signed.sif"),
			id:   1,
		},
		{
			name: "DataPartitionSquashFS",
			path: filepath.Join(corpus, "two-groups-signed.sif"),
			id:   2,
		},
		{
			name: "DataPartitionEXT3",
			path: filepath.Join(corpus, "two-groups-signed.sif"),
			id:   3,
		},
		{
			name: "DataSignature",
			path: filepath.Join(corpus, "two-groups-signed.sif"),
			id:   4,
		},
		{
			name: "DataSignatureX509",
			path: filepath.Join(corpus, "two-groups-signed-x509.sif"),
			id:   4,
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

			if tt.wantErr == nil {
				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
			}
		})
	}
}

func TestApp_Dump(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		id      uint32
		wantErr error
	}{
		{
			name:    "NotExist",
			path:    "not-exist.sif",
			wantErr: os.ErrNotExist,
		},
		{
			name:    "InvalidObjectID",
			path:    filepath.Join(corpus, "one-group-signed.sif"),
			id:      0,
			wantErr: sif.ErrInvalidObjectID,
		},
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

			if tt.wantErr == nil {
				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
			}
		})
	}
}
