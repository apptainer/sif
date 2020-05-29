// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sylabs/sif/pkg/sif"
	"golang.org/x/crypto/openpgp"
)

func TestNewVerifier(t *testing.T) {
	emptyImage, err := sif.LoadContainer(filepath.Join("testdata", "images", "empty.sif"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer emptyImage.UnloadContainer() // nolint:errcheck

	oneGroupImage, err := sif.LoadContainer(filepath.Join("testdata", "images", "one-group.sif"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupImage.UnloadContainer() // nolint:errcheck

	twoGroupImage, err := sif.LoadContainer(filepath.Join("testdata", "images", "two-groups.sif"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer twoGroupImage.UnloadContainer() // nolint:errcheck

	kr := openpgp.EntityList{getTestEntity(t)}

	tests := []struct {
		name        string
		fi          *sif.FileImage
		opts        []VerifierOpt
		wantErr     error
		wantKeyring openpgp.KeyRing
		wantGroups  []uint32
		wantObjects []uint32
		wantLegacy  bool
		wantTasks   int
	}{
		{
			name:    "NilFileImage",
			fi:      nil,
			wantErr: errNilFileImage,
		},
		{
			name:        "NoGroupsFound",
			fi:          &emptyImage,
			opts:        []VerifierOpt{},
			wantKeyring: kr,
			wantErr:     errNoGroupsFound,
		},
		{
			name:    "InvalidGroupID",
			fi:      &emptyImage,
			opts:    []VerifierOpt{OptVerifyGroup(0)},
			wantErr: errInvalidGroupID,
		},
		{
			name:    "GroupNotFound",
			fi:      &emptyImage,
			opts:    []VerifierOpt{OptVerifyWithKeyRing(kr), OptVerifyGroup(1)},
			wantErr: errGroupNotFound,
		},
		{
			name:    "InvalidObjectID",
			fi:      &emptyImage,
			opts:    []VerifierOpt{OptVerifyObject(0)},
			wantErr: errInvalidObjectID,
		},
		{
			name:    "ObjectNotFound",
			fi:      &emptyImage,
			opts:    []VerifierOpt{OptVerifyWithKeyRing(kr), OptVerifyObject(1)},
			wantErr: errObjectNotFound,
		},
		{
			name:       "OneGroupDefaults",
			fi:         &oneGroupImage,
			opts:       []VerifierOpt{},
			wantGroups: []uint32{1},
			wantTasks:  1,
		},
		{
			name:       "TwoGroupDefaults",
			fi:         &twoGroupImage,
			opts:       []VerifierOpt{},
			wantGroups: []uint32{1, 2},
			wantTasks:  2,
		},
		{
			name:        "OptVerifyWithKeyRing",
			fi:          &twoGroupImage,
			opts:        []VerifierOpt{OptVerifyWithKeyRing(kr)},
			wantKeyring: kr,
			wantGroups:  []uint32{1, 2},
			wantTasks:   2,
		},
		{
			name:       "OptVerifyGroupDuplicate",
			fi:         &twoGroupImage,
			opts:       []VerifierOpt{OptVerifyGroup(1), OptVerifyGroup(1)},
			wantGroups: []uint32{1},
			wantTasks:  1,
		},
		{
			name:       "OptVerifyGroup1",
			fi:         &twoGroupImage,
			opts:       []VerifierOpt{OptVerifyGroup(1)},
			wantGroups: []uint32{1},
			wantTasks:  1,
		},
		{
			name:       "OptVerifyGroup2",
			fi:         &twoGroupImage,
			opts:       []VerifierOpt{OptVerifyGroup(2)},
			wantGroups: []uint32{2},
			wantTasks:  1,
		},
		{
			name:       "OptVerifyGroups",
			fi:         &twoGroupImage,
			opts:       []VerifierOpt{OptVerifyGroup(1), OptVerifyGroup(2)},
			wantGroups: []uint32{1, 2},
			wantTasks:  2,
		},
		{
			name:        "OptVerifyObjectDuplicate",
			fi:          &twoGroupImage,
			opts:        []VerifierOpt{OptVerifyObject(1), OptVerifyObject(1)},
			wantObjects: []uint32{1},
			wantTasks:   1,
		},
		{
			name:        "OptVerifyObject1",
			fi:          &twoGroupImage,
			opts:        []VerifierOpt{OptVerifyObject(1)},
			wantObjects: []uint32{1},
			wantTasks:   1,
		},
		{
			name:        "OptVerifyObject2",
			fi:          &twoGroupImage,
			opts:        []VerifierOpt{OptVerifyObject(2)},
			wantObjects: []uint32{2},
			wantTasks:   1,
		},
		{
			name:        "OptVerifyObject3",
			fi:          &twoGroupImage,
			opts:        []VerifierOpt{OptVerifyObject(3)},
			wantObjects: []uint32{3},
			wantTasks:   1,
		},
		{
			name:        "OptVerifyObjects",
			fi:          &twoGroupImage,
			opts:        []VerifierOpt{OptVerifyObject(1), OptVerifyObject(2), OptVerifyObject(3)},
			wantObjects: []uint32{1, 2, 3},
			wantTasks:   3,
		},
		{
			name:       "OptVerifyLegacy",
			fi:         &twoGroupImage,
			opts:       []VerifierOpt{OptVerifyLegacy()},
			wantGroups: []uint32{1, 2},
			wantLegacy: true,
		},
		{
			name:       "OptVerifyLegacyGroup1",
			fi:         &twoGroupImage,
			opts:       []VerifierOpt{OptVerifyLegacy(), OptVerifyGroup(1)},
			wantGroups: []uint32{1},
			wantLegacy: true,
		},
		{
			name:        "OptVerifyLegacyObject1",
			fi:          &twoGroupImage,
			opts:        []VerifierOpt{OptVerifyLegacy(), OptVerifyObject(1)},
			wantObjects: []uint32{1},
			wantLegacy:  true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(tt.fi, tt.opts...)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := v.f, tt.fi; got != want {
					t.Errorf("got FileImage %v, want %v", got, want)
				}

				if got, want := v.keyRing, tt.wantKeyring; !reflect.DeepEqual(got, want) {
					t.Errorf("got key ring %v, want %v", got, want)
				}

				if got, want := v.groups, tt.wantGroups; !reflect.DeepEqual(got, want) {
					t.Errorf("got groups %v, want %v", got, want)
				}

				if got, want := v.objects, tt.wantObjects; !reflect.DeepEqual(got, want) {
					t.Errorf("got objects %v, want %v", got, want)
				}

				if got, want := v.isLegacy, tt.wantLegacy; got != want {
					t.Errorf("got legacy %v, want %v", got, want)
				}

				if got, want := len(v.tasks), tt.wantTasks; got != want {
					t.Errorf("got %v tasks, want %v", got, want)
				}
			}
		})
	}
}

type mockVerifier struct {
	err error
}

func (v mockVerifier) verifyWithKeyRing(kr openpgp.KeyRing) error {
	return v.err
}

func TestVerifier_Verify(t *testing.T) {
	kr := openpgp.EntityList{getTestEntity(t)}

	tests := []struct {
		name    string
		kr      openpgp.KeyRing
		tasks   []verifyTask
		wantErr error
	}{
		{
			name:    "ErrNoKeyMaterial",
			tasks:   []verifyTask{mockVerifier{}},
			wantErr: ErrNoKeyMaterial,
		},
		{
			name:    "EOF",
			kr:      kr,
			tasks:   []verifyTask{mockVerifier{err: io.EOF}},
			wantErr: io.EOF,
		},
		{
			name:  "OK",
			kr:    kr,
			tasks: []verifyTask{mockVerifier{}},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			v := Verifier{
				keyRing: tt.kr,
				tasks:   tt.tasks,
			}

			if got, want := v.Verify(), tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}
		})
	}
}
