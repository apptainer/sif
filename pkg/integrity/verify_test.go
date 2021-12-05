// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/apptainer/sif/v2/pkg/sif"
)

func TestGroupVerifier_fingerprints(t *testing.T) {
	oneGroupImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupImage.UnloadContainer() // nolint:errcheck

	oneGroupSignedImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group-signed.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupSignedImage.UnloadContainer() // nolint:errcheck

	e := getTestEntity(t)

	tests := []struct {
		name    string
		f       *sif.FileImage
		groupID uint32
		wantFPs [][]byte
		wantErr error
	}{
		{
			name:    "Unsigned",
			f:       oneGroupImage,
			groupID: 1,
		},
		{
			name:    "Signed",
			f:       oneGroupSignedImage,
			groupID: 1,
			wantFPs: [][]byte{e.PrimaryKey.Fingerprint},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			v := &groupVerifier{
				f:       tt.f,
				groupID: tt.groupID,
			}

			got, err := v.fingerprints()

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("got error %v, want %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(got, tt.wantFPs) {
				t.Errorf("got fingerprints %v, want %v", got, tt.wantFPs)
			}
		})
	}
}

func TestGroupVerifier_verifyWithKeyRing(t *testing.T) {
	oneGroupImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupImage.UnloadContainer() // nolint:errcheck

	oneGroupSignedImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group-signed.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupSignedImage.UnloadContainer() // nolint:errcheck

	e := getTestEntity(t)
	kr := openpgp.EntityList{e}

	tests := []struct {
		name            string
		f               *sif.FileImage
		testCallback    bool
		ignoreError     bool
		groupID         uint32
		objectIDs       []uint32
		subsetOK        bool
		kr              openpgp.KeyRing
		wantCBSignature uint32
		wantCBVerified  []uint32
		wantCBEntity    *openpgp.Entity
		wantCBErr       error
		wantErr         error
	}{
		{
			name:      "SignatureNotFound",
			f:         oneGroupImage,
			groupID:   1,
			objectIDs: []uint32{1, 2},
			kr:        kr,
			wantErr:   &SignatureNotFoundError{},
		},
		{
			name:      "SignedObjectNotFound",
			f:         oneGroupSignedImage,
			groupID:   1,
			objectIDs: []uint32{1},
			kr:        kr,
			wantErr:   errSignedObjectNotFound,
		},
		{
			name:      "UnknownIssuer",
			f:         oneGroupSignedImage,
			groupID:   1,
			objectIDs: []uint32{1, 2},
			kr:        openpgp.EntityList{},
			wantErr:   &SignatureNotValidError{ID: 3, Err: pgperrors.ErrUnknownIssuer},
		},
		{
			name:            "IgnoreError",
			f:               oneGroupSignedImage,
			testCallback:    true,
			ignoreError:     true,
			groupID:         1,
			objectIDs:       []uint32{1, 2},
			kr:              openpgp.EntityList{},
			wantCBSignature: 3,
			wantCBErr:       &SignatureNotValidError{ID: 3, Err: pgperrors.ErrUnknownIssuer},
			wantErr:         nil,
		},
		{
			name:      "OneGroupSigned",
			f:         oneGroupSignedImage,
			groupID:   1,
			objectIDs: []uint32{1, 2},
			kr:        kr,
		},
		{
			name:            "OneGroupSignedWithCallback",
			f:               oneGroupSignedImage,
			testCallback:    true,
			groupID:         1,
			objectIDs:       []uint32{1, 2},
			kr:              kr,
			wantCBSignature: 3,
			wantCBVerified:  []uint32{1, 2},
			wantCBEntity:    e,
		},
		{
			name:      "OneGroupSignedSubset",
			f:         oneGroupSignedImage,
			groupID:   1,
			objectIDs: []uint32{1},
			subsetOK:  true,
			kr:        kr,
		},
		{
			name:            "OneGroupSignedSubsetWithCallback",
			f:               oneGroupSignedImage,
			testCallback:    true,
			groupID:         1,
			objectIDs:       []uint32{1},
			subsetOK:        true,
			kr:              kr,
			wantCBSignature: 3,
			wantCBVerified:  []uint32{1},
			wantCBEntity:    e,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ods := make([]sif.Descriptor, len(tt.objectIDs))
			for i, id := range tt.objectIDs {
				od, err := tt.f.GetDescriptor(sif.WithID(id))
				if err != nil {
					t.Fatal(err)
				}
				ods[i] = od
			}

			// Test callback functionality, if requested.
			var cb VerifyCallback

			//nolint:dupl
			if tt.testCallback {
				cb = func(r VerifyResult) bool {
					if got, want := r.Signature().ID(), tt.wantCBSignature; got != want {
						t.Errorf("got signature %v, want %v", got, want)
					}

					if got, want := len(r.Verified()), len(tt.wantCBVerified); got != want {
						t.Fatalf("got %v verified objects, want %v", got, want)
					}
					for i, od := range r.Verified() {
						if got, want := od.ID(), tt.wantCBVerified[i]; got != want {
							t.Errorf("got verified ID %v, want %v", got, want)
						}
					}

					if got, want := r.Entity(), tt.wantCBEntity; got != want {
						t.Errorf("got entity %v, want %v", got, want)
					}

					if got, want := r.Error(), tt.wantCBErr; !errors.Is(got, want) {
						t.Errorf("got error %v, want %v", got, want)
					}

					return tt.ignoreError
				}
			}

			v := &groupVerifier{
				f:        tt.f,
				cb:       cb,
				groupID:  tt.groupID,
				ods:      ods,
				subsetOK: tt.subsetOK,
			}

			if got, want := v.verifyWithKeyRing(tt.kr), tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}
		})
	}
}

func TestLegacyGroupVerifier_fingerprints(t *testing.T) {
	oneGroupImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupImage.UnloadContainer() // nolint:errcheck

	oneGroupImageSigned, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group-signed-legacy-group.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupImageSigned.UnloadContainer() // nolint:errcheck

	e := getTestEntity(t)

	tests := []struct {
		name    string
		f       *sif.FileImage
		id      uint32
		wantFPs [][]byte
		wantErr error
	}{
		{
			name: "Unsigned",
			f:    oneGroupImage,
			id:   1,
		},
		{
			name:    "Signed",
			f:       oneGroupImageSigned,
			id:      1,
			wantFPs: [][]byte{e.PrimaryKey.Fingerprint},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			v := &legacyGroupVerifier{
				f:       tt.f,
				groupID: 1,
			}

			got, err := v.fingerprints()

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("got error %v, want %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(got, tt.wantFPs) {
				t.Errorf("got fingerprints %v, want %v", got, tt.wantFPs)
			}
		})
	}
}

func TestLegacyGroupVerifier_verifyWithKeyRing(t *testing.T) {
	oneGroupImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupImage.UnloadContainer() // nolint:errcheck

	oneGroupSignedImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group-signed-legacy-group.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupSignedImage.UnloadContainer() // nolint:errcheck

	e := getTestEntity(t)
	kr := openpgp.EntityList{e}

	tests := []struct {
		name            string
		f               *sif.FileImage
		testCallback    bool
		ignoreError     bool
		groupID         uint32
		kr              openpgp.KeyRing
		wantCBSignature uint32
		wantCBVerified  []uint32
		wantCBEntity    *openpgp.Entity
		wantCBErr       error
		wantErr         error
	}{
		{
			name:    "SignatureNotFound",
			f:       oneGroupImage,
			groupID: 1,
			kr:      kr,
			wantErr: &SignatureNotFoundError{},
		},
		{
			name:    "UnknownIssuer",
			f:       oneGroupSignedImage,
			groupID: 1,
			kr:      openpgp.EntityList{},
			wantErr: pgperrors.ErrUnknownIssuer,
		},
		{
			name:            "IgnoreError",
			f:               oneGroupSignedImage,
			testCallback:    true,
			ignoreError:     true,
			groupID:         1,
			kr:              openpgp.EntityList{},
			wantCBSignature: 3,
			wantCBErr:       pgperrors.ErrUnknownIssuer,
			wantErr:         nil,
		},
		{
			name:    "OneGroupSigned",
			f:       oneGroupSignedImage,
			groupID: 1,
			kr:      kr,
		},
		{
			name:            "OneGroupSignedWithCallback",
			f:               oneGroupSignedImage,
			testCallback:    true,
			groupID:         1,
			kr:              kr,
			wantCBSignature: 3,
			wantCBVerified:  []uint32{1, 2},
			wantCBEntity:    e,
		},
		{
			name:    "OneGroupSignedSubset",
			f:       oneGroupSignedImage,
			groupID: 1,
			kr:      kr,
		},
		{
			name:            "OneGroupSignedSubsetWithCallback",
			f:               oneGroupSignedImage,
			testCallback:    true,
			groupID:         1,
			kr:              kr,
			wantCBSignature: 3,
			wantCBVerified:  []uint32{1, 2},
			wantCBEntity:    e,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Test callback functionality, if requested.
			var cb VerifyCallback

			//nolint:dupl
			if tt.testCallback {
				cb = func(r VerifyResult) bool {
					if got, want := r.Signature().ID(), tt.wantCBSignature; got != want {
						t.Errorf("got signature %v, want %v", got, want)
					}

					if got, want := len(r.Verified()), len(tt.wantCBVerified); got != want {
						t.Fatalf("got %v verified objects, want %v", got, want)
					}
					for i, od := range r.Verified() {
						if got, want := od.ID(), tt.wantCBVerified[i]; got != want {
							t.Errorf("got verified ID %v, want %v", got, want)
						}
					}

					if got, want := r.Entity(), tt.wantCBEntity; got != want {
						t.Errorf("got entity %v, want %v", got, want)
					}

					if got, want := r.Error(), tt.wantCBErr; !errors.Is(got, want) {
						t.Errorf("got error %v, want %v", got, want)
					}

					return tt.ignoreError
				}
			}

			ods, err := getGroupObjects(tt.f, tt.groupID)
			if err != nil {
				t.Fatal(err)
			}

			v := &legacyGroupVerifier{
				f:       tt.f,
				cb:      cb,
				groupID: tt.groupID,
				ods:     ods,
			}

			if got, want := v.verifyWithKeyRing(tt.kr), tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}
		})
	}
}

func TestLegacyObjectVerifier_fingerprints(t *testing.T) {
	oneGroupImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupImage.UnloadContainer() // nolint:errcheck

	oneGroupImageSigned, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group-signed-legacy-all.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupImageSigned.UnloadContainer() // nolint:errcheck

	e := getTestEntity(t)

	tests := []struct {
		name    string
		f       *sif.FileImage
		id      uint32
		wantFPs [][]byte
		wantErr error
	}{
		{
			name: "Unsigned",
			f:    oneGroupImage,
			id:   1,
		},
		{
			name:    "Signed",
			f:       oneGroupImageSigned,
			id:      1,
			wantFPs: [][]byte{e.PrimaryKey.Fingerprint},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			od, err := tt.f.GetDescriptor(sif.WithID(tt.id))
			if err != nil {
				t.Fatal(err)
			}

			v := &legacyObjectVerifier{
				f:  tt.f,
				od: od,
			}

			got, err := v.fingerprints()

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("got error %v, want %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(got, tt.wantFPs) {
				t.Errorf("got fingerprints %v, want %v", got, tt.wantFPs)
			}
		})
	}
}

func TestLegacyObjectVerifier_verifyWithKeyRing(t *testing.T) {
	oneGroupImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupImage.UnloadContainer() // nolint:errcheck

	oneGroupSignedImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group-signed-legacy-all.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupSignedImage.UnloadContainer() // nolint:errcheck

	e := getTestEntity(t)
	kr := openpgp.EntityList{e}

	tests := []struct {
		name            string
		f               *sif.FileImage
		testCallback    bool
		ignoreError     bool
		id              uint32
		kr              openpgp.KeyRing
		wantCBSignature uint32
		wantCBVerified  []uint32
		wantCBEntity    *openpgp.Entity
		wantCBErr       error
		wantErr         error
	}{
		{
			name:    "SignatureNotFound",
			f:       oneGroupImage,
			id:      1,
			kr:      kr,
			wantErr: &SignatureNotFoundError{},
		},
		{
			name:    "UnknownIssuer",
			f:       oneGroupSignedImage,
			id:      1,
			kr:      openpgp.EntityList{},
			wantErr: pgperrors.ErrUnknownIssuer,
		},
		{
			name:            "IgnoreError",
			f:               oneGroupSignedImage,
			testCallback:    true,
			ignoreError:     true,
			id:              1,
			kr:              openpgp.EntityList{},
			wantCBSignature: 3,
			wantCBErr:       pgperrors.ErrUnknownIssuer,
			wantErr:         nil,
		},
		{
			name: "OneGroupSigned",
			f:    oneGroupSignedImage,
			id:   1,
			kr:   kr,
		},
		{
			name:            "OneGroupSignedWithCallback",
			f:               oneGroupSignedImage,
			testCallback:    true,
			id:              1,
			kr:              kr,
			wantCBSignature: 3,
			wantCBVerified:  []uint32{1},
			wantCBEntity:    e,
		},
		{
			name: "OneGroupSignedSubset",
			f:    oneGroupSignedImage,
			id:   1,
			kr:   kr,
		},
		{
			name:            "OneGroupSignedSubsetWithCallback",
			f:               oneGroupSignedImage,
			testCallback:    true,
			id:              1,
			kr:              kr,
			wantCBSignature: 3,
			wantCBVerified:  []uint32{1},
			wantCBEntity:    e,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Test callback functionality, if requested.
			var cb VerifyCallback

			//nolint:dupl
			if tt.testCallback {
				cb = func(r VerifyResult) bool {
					if got, want := r.Signature().ID(), tt.wantCBSignature; got != want {
						t.Errorf("got signature %v, want %v", got, want)
					}

					if got, want := len(r.Verified()), len(tt.wantCBVerified); got != want {
						t.Fatalf("got %v verified objects, want %v", got, want)
					}
					for i, od := range r.Verified() {
						if got, want := od.ID(), tt.wantCBVerified[i]; got != want {
							t.Errorf("got verified ID %v, want %v", got, want)
						}
					}

					if got, want := r.Entity(), tt.wantCBEntity; got != want {
						t.Errorf("got entity %v, want %v", got, want)
					}

					if got, want := r.Error(), tt.wantCBErr; !errors.Is(got, want) {
						t.Errorf("got error %v, want %v", got, want)
					}

					return tt.ignoreError
				}
			}

			od, err := tt.f.GetDescriptor(sif.WithID(tt.id))
			if err != nil {
				t.Fatal(err)
			}

			v := &legacyObjectVerifier{
				f:  tt.f,
				cb: cb,
				od: od,
			}

			if got, want := v.verifyWithKeyRing(tt.kr), tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}
		})
	}
}

func TestNewVerifier(t *testing.T) {
	emptyImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "empty.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer emptyImage.UnloadContainer() // nolint:errcheck

	oneGroupImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupImage.UnloadContainer() // nolint:errcheck

	twoGroupImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "two-groups.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer twoGroupImage.UnloadContainer() // nolint:errcheck

	kr := openpgp.EntityList{getTestEntity(t)}

	cb := func(r VerifyResult) bool { return false }

	tests := []struct {
		name          string
		fi            *sif.FileImage
		opts          []VerifierOpt
		wantErr       error
		wantKeyring   openpgp.KeyRing
		wantGroups    []uint32
		wantObjects   []uint32
		wantLegacy    bool
		wantLegacyAll bool
		wantCallback  bool
		wantTasks     int
	}{
		{
			name:    "NilFileImage",
			fi:      nil,
			wantErr: errNilFileImage,
		},
		{
			name:    "NoGroupsFound",
			fi:      emptyImage,
			opts:    []VerifierOpt{},
			wantErr: errNoGroupsFound,
		},
		{
			name:    "InvalidGroupID",
			fi:      emptyImage,
			opts:    []VerifierOpt{OptVerifyGroup(0)},
			wantErr: sif.ErrInvalidGroupID,
		},
		{
			name:    "NoObjects",
			fi:      emptyImage,
			opts:    []VerifierOpt{OptVerifyWithKeyRing(kr), OptVerifyGroup(1)},
			wantErr: sif.ErrNoObjects,
		},
		{
			name:    "GroupNotFound",
			fi:      oneGroupImage,
			opts:    []VerifierOpt{OptVerifyWithKeyRing(kr), OptVerifyGroup(2)},
			wantErr: errGroupNotFound,
		},
		{
			name:    "GroupNotFoundLegacy",
			fi:      oneGroupImage,
			opts:    []VerifierOpt{OptVerifyWithKeyRing(kr), OptVerifyGroup(2), OptVerifyLegacy()},
			wantErr: errGroupNotFound,
		},
		{
			name:    "InvalidObjectID",
			fi:      emptyImage,
			opts:    []VerifierOpt{OptVerifyObject(0)},
			wantErr: sif.ErrInvalidObjectID,
		},
		{
			name:    "ObjectNotFound",
			fi:      oneGroupImage,
			opts:    []VerifierOpt{OptVerifyObject(3)},
			wantErr: sif.ErrObjectNotFound,
		},
		{
			name:    "ObjectNotFoundLegacy",
			fi:      oneGroupImage,
			opts:    []VerifierOpt{OptVerifyObject(3), OptVerifyLegacy()},
			wantErr: sif.ErrObjectNotFound,
		},
		{
			name:       "OneGroupDefaults",
			fi:         oneGroupImage,
			opts:       []VerifierOpt{},
			wantGroups: []uint32{1},
			wantTasks:  1,
		},
		{
			name:       "TwoGroupDefaults",
			fi:         twoGroupImage,
			opts:       []VerifierOpt{},
			wantGroups: []uint32{1, 2},
			wantTasks:  2,
		},
		{
			name:        "OptVerifyWithKeyRing",
			fi:          twoGroupImage,
			opts:        []VerifierOpt{OptVerifyWithKeyRing(kr)},
			wantKeyring: kr,
			wantGroups:  []uint32{1, 2},
			wantTasks:   2,
		},
		{
			name:       "OptVerifyGroupDuplicate",
			fi:         twoGroupImage,
			opts:       []VerifierOpt{OptVerifyGroup(1), OptVerifyGroup(1)},
			wantGroups: []uint32{1},
			wantTasks:  1,
		},
		{
			name:       "OptVerifyGroup1",
			fi:         twoGroupImage,
			opts:       []VerifierOpt{OptVerifyGroup(1)},
			wantGroups: []uint32{1},
			wantTasks:  1,
		},
		{
			name:       "OptVerifyGroup2",
			fi:         twoGroupImage,
			opts:       []VerifierOpt{OptVerifyGroup(2)},
			wantGroups: []uint32{2},
			wantTasks:  1,
		},
		{
			name:       "OptVerifyGroups",
			fi:         twoGroupImage,
			opts:       []VerifierOpt{OptVerifyGroup(1), OptVerifyGroup(2)},
			wantGroups: []uint32{1, 2},
			wantTasks:  2,
		},
		{
			name:        "OptVerifyObjectDuplicate",
			fi:          twoGroupImage,
			opts:        []VerifierOpt{OptVerifyObject(1), OptVerifyObject(1)},
			wantObjects: []uint32{1},
			wantTasks:   1,
		},
		{
			name:        "OptVerifyObject1",
			fi:          twoGroupImage,
			opts:        []VerifierOpt{OptVerifyObject(1)},
			wantObjects: []uint32{1},
			wantTasks:   1,
		},
		{
			name:        "OptVerifyObject2",
			fi:          twoGroupImage,
			opts:        []VerifierOpt{OptVerifyObject(2)},
			wantObjects: []uint32{2},
			wantTasks:   1,
		},
		{
			name:        "OptVerifyObject3",
			fi:          twoGroupImage,
			opts:        []VerifierOpt{OptVerifyObject(3)},
			wantObjects: []uint32{3},
			wantTasks:   1,
		},
		{
			name:        "OptVerifyObjects",
			fi:          twoGroupImage,
			opts:        []VerifierOpt{OptVerifyObject(1), OptVerifyObject(2), OptVerifyObject(3)},
			wantObjects: []uint32{1, 2, 3},
			wantTasks:   3,
		},
		{
			name:       "OptVerifyLegacy",
			fi:         twoGroupImage,
			opts:       []VerifierOpt{OptVerifyLegacy()},
			wantGroups: []uint32{1, 2},
			wantLegacy: true,
			wantTasks:  2,
		},
		{
			name:       "OptVerifyLegacyGroup1",
			fi:         twoGroupImage,
			opts:       []VerifierOpt{OptVerifyLegacy(), OptVerifyGroup(1)},
			wantGroups: []uint32{1},
			wantLegacy: true,
			wantTasks:  1,
		},
		{
			name:        "OptVerifyLegacyObject1",
			fi:          twoGroupImage,
			opts:        []VerifierOpt{OptVerifyLegacy(), OptVerifyObject(1)},
			wantObjects: []uint32{1},
			wantLegacy:  true,
			wantTasks:   1,
		},
		{
			name:          "OptVerifyLegacyAll",
			fi:            twoGroupImage,
			opts:          []VerifierOpt{OptVerifyLegacyAll()},
			wantObjects:   []uint32{1, 2, 3},
			wantLegacy:    true,
			wantLegacyAll: true,
			wantTasks:     3,
		},
		{
			name:         "OptVerifyCallback",
			fi:           twoGroupImage,
			opts:         []VerifierOpt{OptVerifyCallback(cb)},
			wantGroups:   []uint32{1, 2},
			wantCallback: true,
			wantTasks:    2,
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

				if got, want := v.kr, tt.wantKeyring; !reflect.DeepEqual(got, want) {
					t.Errorf("got key ring %v, want %v", got, want)
				}

				if got, want := len(v.tasks), tt.wantTasks; got != want {
					t.Errorf("got %v tasks, want %v", got, want)
				}
			}
		})
	}
}

type mockVerifier struct {
	fps [][]byte
	err error
}

func (v mockVerifier) fingerprints() ([][]byte, error) {
	return v.fps, v.err
}

func (v mockVerifier) verifyWithKeyRing(kr openpgp.KeyRing) error {
	return v.err
}

func TestVerifier_AnySignedBy(t *testing.T) {
	fp1 := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
	}

	fp2 := []byte{
		0x13, 0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a,
		0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
	}

	tests := []struct {
		name             string
		tasks            []verifyTask
		wantErr          error
		wantFingerprints [][]byte
	}{
		{
			name: "OneTaskEOF",
			tasks: []verifyTask{
				mockVerifier{err: io.EOF},
			},
			wantErr: io.EOF,
		},
		{
			name: "TwoTasksEOF",
			tasks: []verifyTask{
				mockVerifier{fps: [][]byte{fp1}},
				mockVerifier{err: io.EOF},
			},
			wantErr: io.EOF,
		},
		{
			name: "OneTaskOneFP",
			tasks: []verifyTask{
				mockVerifier{fps: [][]byte{fp1}},
			},
			wantFingerprints: [][]byte{fp1},
		},
		{
			name: "TwoTasksSameFP",
			tasks: []verifyTask{
				mockVerifier{fps: [][]byte{fp1}},
				mockVerifier{fps: [][]byte{fp1}},
			},
			wantFingerprints: [][]byte{fp1},
		},
		{
			name: "TwoTasksTwoFP",
			tasks: []verifyTask{
				mockVerifier{fps: [][]byte{fp1}},
				mockVerifier{fps: [][]byte{fp2}},
			},
			wantFingerprints: [][]byte{fp1, fp2},
		},
		{
			name: "KitchenSink",
			tasks: []verifyTask{
				mockVerifier{fps: [][]byte{}},
				mockVerifier{fps: [][]byte{fp1}},
				mockVerifier{fps: [][]byte{fp2}},
				mockVerifier{fps: [][]byte{fp1, fp2}},
			},
			wantFingerprints: [][]byte{fp1, fp2},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			v := Verifier{tasks: tt.tasks}

			fp, err := v.AnySignedBy()

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if got, want := fp, tt.wantFingerprints; !reflect.DeepEqual(got, want) {
				t.Fatalf("got fingerprints %v, want %v", got, want)
			}
		})
	}
}

func TestVerifier_AllSignedBy(t *testing.T) {
	fp1 := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
	}

	fp2 := []byte{
		0x13, 0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a,
		0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
	}

	tests := []struct {
		name             string
		tasks            []verifyTask
		wantErr          error
		wantFingerprints [][]byte
	}{
		{
			name: "OneTaskEOF",
			tasks: []verifyTask{
				mockVerifier{err: io.EOF},
			},
			wantErr: io.EOF,
		},
		{
			name: "TwoTasksEOF",
			tasks: []verifyTask{
				mockVerifier{fps: [][]byte{fp1}},
				mockVerifier{err: io.EOF},
			},
			wantErr: io.EOF,
		},
		{
			name: "OneTaskNoFP",
			tasks: []verifyTask{
				mockVerifier{fps: [][]byte{}},
			},
		},
		{
			name: "OneTaskOneFP",
			tasks: []verifyTask{
				mockVerifier{fps: [][]byte{fp1}},
			},
			wantFingerprints: [][]byte{fp1},
		},
		{
			name: "TwoTasksSameFP",
			tasks: []verifyTask{
				mockVerifier{fps: [][]byte{fp1}},
				mockVerifier{fps: [][]byte{fp1}},
			},
			wantFingerprints: [][]byte{fp1},
		},
		{
			name: "TwoTasksTwoFP",
			tasks: []verifyTask{
				mockVerifier{fps: [][]byte{fp1}},
				mockVerifier{fps: [][]byte{fp2}},
			},
		},
		{
			name: "KitchenSink",
			tasks: []verifyTask{
				mockVerifier{fps: [][]byte{}},
				mockVerifier{fps: [][]byte{fp1}},
				mockVerifier{fps: [][]byte{fp2}},
				mockVerifier{fps: [][]byte{fp1, fp2}},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			v := Verifier{tasks: tt.tasks}

			fp, err := v.AllSignedBy()

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if got, want := fp, tt.wantFingerprints; !reflect.DeepEqual(got, want) {
				t.Fatalf("got fingerprints %v, want %v", got, want)
			}
		})
	}
}

func TestVerifier_Verify(t *testing.T) {
	oneGroupSignedImage, err := sif.LoadContainerFromPath(
		filepath.Join(corpus, "one-group-signed.sif"),
		sif.OptLoadWithFlag(os.O_RDONLY),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroupSignedImage.UnloadContainer() // nolint:errcheck

	kr := openpgp.EntityList{getTestEntity(t)}

	tests := []struct {
		name    string
		f       *sif.FileImage
		kr      openpgp.KeyRing
		tasks   []verifyTask
		wantErr error
	}{
		{
			name:    "ErrNoKeyMaterial",
			f:       oneGroupSignedImage,
			tasks:   []verifyTask{mockVerifier{}},
			wantErr: ErrNoKeyMaterial,
		},
		{
			name:    "EOF",
			f:       oneGroupSignedImage,
			kr:      kr,
			tasks:   []verifyTask{mockVerifier{err: io.EOF}},
			wantErr: io.EOF,
		},
		{
			name:  "OK",
			f:     oneGroupSignedImage,
			kr:    kr,
			tasks: []verifyTask{mockVerifier{}},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			v := Verifier{
				f:     tt.f,
				kr:    tt.kr,
				tasks: tt.tasks,
			}

			if got, want := v.Verify(), tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}
		})
	}
}
