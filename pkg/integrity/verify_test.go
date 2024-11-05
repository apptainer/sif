// Copyright (c) Contributors to the Apptainer project, established as
//
//	Apptainer a Series of LF Projects LLC.
//	For website terms of use, trademark policy, privacy policy and other
//	project policies see https://lfprojects.org/policies
//
// Copyright (c) 2020-2024, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.
package integrity

import (
	"context"
	"crypto"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/apptainer/sif/v2/pkg/sif"
)

func TestGroupVerifier_signatures(t *testing.T) {
	oneGroupImage := loadContainer(t, filepath.Join(corpus, "one-group.sif"))
	oneGroupSignedImage := loadContainer(t, filepath.Join(corpus, "one-group-signed-pgp.sif"))

	sigs, err := oneGroupSignedImage.GetDescriptors(sif.WithDataType(sif.DataSignature))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		f        *sif.FileImage
		groupID  uint32
		wantSigs []sif.Descriptor
		wantErr  error
	}{
		{
			name:    "Unsigned",
			f:       oneGroupImage,
			groupID: 1,
			wantErr: &SignatureNotFoundError{},
		},
		{
			name:     "Signed",
			f:        oneGroupSignedImage,
			groupID:  1,
			wantSigs: sigs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &groupVerifier{
				f:       tt.f,
				groupID: tt.groupID,
			}

			sigs, err := v.signatures()

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if got, want := sigs, tt.wantSigs; !reflect.DeepEqual(got, want) {
				t.Errorf("got signatures %v, want %v", got, want)
			}
		})
	}
}

func TestGroupVerifier_verify(t *testing.T) {
	oneGroupSignedImage := loadContainer(t, filepath.Join(corpus, "one-group-signed-pgp.sif"))

	sig, err := oneGroupSignedImage.GetDescriptor(sif.WithDataType(sif.DataSignature))
	if err != nil {
		t.Fatal(err)
	}

	verified, err := oneGroupSignedImage.GetDescriptors(sif.WithGroupID(1))
	if err != nil {
		t.Fatal(err)
	}

	e := getTestEntity(t)

	tests := []struct {
		name         string
		f            *sif.FileImage
		groupID      uint32
		objectIDs    []uint32
		subsetOK     bool
		sig          sif.Descriptor
		de           decoder
		wantErr      error
		wantVerified []sif.Descriptor
		wantEntity   *openpgp.Entity
	}{
		{
			name:       "SignedObjectNotFound",
			f:          oneGroupSignedImage,
			groupID:    1,
			objectIDs:  []uint32{1},
			sig:        sig,
			de:         newClearsignDecoder(openpgp.EntityList{e}),
			wantErr:    errSignedObjectNotFound,
			wantEntity: e,
		},
		{
			name:      "UnknownIssuer",
			f:         oneGroupSignedImage,
			groupID:   1,
			objectIDs: []uint32{1, 2},
			sig:       sig,
			de:        newClearsignDecoder(openpgp.EntityList{}),
			wantErr: &SignatureNotValidError{
				ID:  3,
				Err: pgperrors.ErrUnknownIssuer,
			},
		},
		{
			name:         "OneGroupSigned",
			f:            oneGroupSignedImage,
			groupID:      1,
			objectIDs:    []uint32{1, 2},
			sig:          sig,
			de:           newClearsignDecoder(openpgp.EntityList{e}),
			wantVerified: verified,
			wantEntity:   e,
		},
		{
			name:         "OneGroupSignedSubset",
			f:            oneGroupSignedImage,
			groupID:      1,
			objectIDs:    []uint32{1},
			subsetOK:     true,
			sig:          sig,
			de:           newClearsignDecoder(openpgp.EntityList{e}),
			wantVerified: verified[:1],
			wantEntity:   e,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ods := make([]sif.Descriptor, len(tt.objectIDs))
			for i, id := range tt.objectIDs {
				od, err := tt.f.GetDescriptor(sif.WithID(id))
				if err != nil {
					t.Fatal(err)
				}
				ods[i] = od
			}

			v := &groupVerifier{
				f:        tt.f,
				groupID:  tt.groupID,
				ods:      ods,
				subsetOK: tt.subsetOK,
			}

			var vr VerifyResult
			err := v.verifySignature(context.Background(), tt.sig, tt.de, &vr)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}

			if got, want := vr.Verified(), tt.wantVerified; !reflect.DeepEqual(got, want) {
				t.Errorf("got verified %v, want %v", got, want)
			}

			if got, want := vr.Entity(), tt.wantEntity; !reflect.DeepEqual(got, want) {
				t.Errorf("got entity %v, want %v", got, want)
			}
		})
	}
}

func TestLegacyGroupVerifier_signatures(t *testing.T) {
	oneGroupImage := loadContainer(t, filepath.Join(corpus, "one-group.sif"))
	oneGroupSignedImage := loadContainer(t, filepath.Join(corpus, "one-group-signed-legacy-group.sif"))

	sigs, err := oneGroupSignedImage.GetDescriptors(sif.WithDataType(sif.DataSignature))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		f        *sif.FileImage
		id       uint32
		wantSigs []sif.Descriptor
		wantErr  error
	}{
		{
			name:    "Unsigned",
			f:       oneGroupImage,
			id:      1,
			wantErr: &SignatureNotFoundError{},
		},
		{
			name:     "Signed",
			f:        oneGroupSignedImage,
			id:       1,
			wantSigs: sigs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &legacyGroupVerifier{
				f:       tt.f,
				groupID: 1,
			}

			sigs, err := v.signatures()

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if got, want := sigs, tt.wantSigs; !reflect.DeepEqual(got, want) {
				t.Errorf("got signatures %v, want %v", got, want)
			}
		})
	}
}

func TestLegacyGroupVerifier_verify(t *testing.T) {
	oneGroupSignedImage := loadContainer(t, filepath.Join(corpus, "one-group-signed-legacy-group.sif"))

	sig, err := oneGroupSignedImage.GetDescriptor(sif.WithDataType(sif.DataSignature))
	if err != nil {
		t.Fatal(err)
	}

	verified, err := oneGroupSignedImage.GetDescriptors(sif.WithGroupID(1))
	if err != nil {
		t.Fatal(err)
	}

	e := getTestEntity(t)

	tests := []struct {
		name         string
		f            *sif.FileImage
		groupID      uint32
		sig          sif.Descriptor
		de           decoder
		wantErr      error
		wantVerified []sif.Descriptor
		wantEntity   *openpgp.Entity
	}{
		{
			name:    "UnknownIssuer",
			f:       oneGroupSignedImage,
			groupID: 1,
			sig:     sig,
			de:      newClearsignDecoder(openpgp.EntityList{}),
			wantErr: &SignatureNotValidError{
				ID:  3,
				Err: pgperrors.ErrUnknownIssuer,
			},
		},
		{
			name:         "OneGroupSigned",
			f:            oneGroupSignedImage,
			groupID:      1,
			sig:          sig,
			de:           newClearsignDecoder(openpgp.EntityList{e}),
			wantVerified: verified,
			wantEntity:   e,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ods, err := getGroupObjects(tt.f, tt.groupID)
			if err != nil {
				t.Fatal(err)
			}

			v := &legacyGroupVerifier{
				f:       tt.f,
				groupID: tt.groupID,
				ods:     ods,
			}

			var vr VerifyResult
			err = v.verifySignature(context.Background(), tt.sig, tt.de, &vr)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}

			if got, want := vr.Verified(), tt.wantVerified; !reflect.DeepEqual(got, want) {
				t.Errorf("got verified %v, want %v", got, want)
			}

			if got, want := vr.Entity(), tt.wantEntity; !reflect.DeepEqual(got, want) {
				t.Errorf("got entity %v, want %v", got, want)
			}
		})
	}
}

func TestLegacyObjectVerifier_signatures(t *testing.T) {
	oneGroupImage := loadContainer(t, filepath.Join(corpus, "one-group.sif"))
	oneGroupSignedImage := loadContainer(t, filepath.Join(corpus, "one-group-signed-legacy-all.sif"))

	sigs, err := oneGroupSignedImage.GetDescriptors(
		sif.WithDataType(sif.DataSignature),
		sif.WithLinkedID(1),
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		f        *sif.FileImage
		id       uint32
		wantSigs []sif.Descriptor
		wantErr  error
	}{
		{
			name:    "Unsigned",
			f:       oneGroupImage,
			id:      1,
			wantErr: &SignatureNotFoundError{},
		},
		{
			name:     "Signed",
			f:        oneGroupSignedImage,
			id:       1,
			wantSigs: sigs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			od, err := tt.f.GetDescriptor(sif.WithID(tt.id))
			if err != nil {
				t.Fatal(err)
			}

			v := &legacyObjectVerifier{
				f:  tt.f,
				od: od,
			}

			sigs, err := v.signatures()

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if got, want := sigs, tt.wantSigs; !reflect.DeepEqual(got, want) {
				t.Errorf("got signatures %v, want %v", got, want)
			}
		})
	}
}

func TestLegacyObjectVerifier_verify(t *testing.T) {
	oneGroupSignedImage := loadContainer(t, filepath.Join(corpus, "one-group-signed-legacy-all.sif"))

	sig, err := oneGroupSignedImage.GetDescriptor(
		sif.WithDataType(sif.DataSignature),
		sif.WithLinkedID(1),
	)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := oneGroupSignedImage.GetDescriptors(sif.WithID(1))
	if err != nil {
		t.Fatal(err)
	}

	e := getTestEntity(t)

	tests := []struct {
		name         string
		f            *sif.FileImage
		id           uint32
		sig          sif.Descriptor
		de           decoder
		wantErr      error
		wantVerified []sif.Descriptor
		wantEntity   *openpgp.Entity
	}{
		{
			name: "UnknownIssuer",
			f:    oneGroupSignedImage,
			id:   1,
			sig:  sig,
			de:   newClearsignDecoder(openpgp.EntityList{}),
			wantErr: &SignatureNotValidError{
				ID:  3,
				Err: pgperrors.ErrUnknownIssuer,
			},
		},
		{
			name:         "OneGroupSigned",
			f:            oneGroupSignedImage,
			id:           1,
			sig:          sig,
			de:           newClearsignDecoder(openpgp.EntityList{e}),
			wantVerified: verified,
			wantEntity:   e,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			od, err := tt.f.GetDescriptor(sif.WithID(tt.id))
			if err != nil {
				t.Fatal(err)
			}

			v := &legacyObjectVerifier{
				f:  tt.f,
				od: od,
			}

			var vr VerifyResult
			err = v.verifySignature(context.Background(), tt.sig, tt.de, &vr)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}

			if got, want := vr.Verified(), tt.wantVerified; !reflect.DeepEqual(got, want) {
				t.Errorf("got verified %v, want %v", got, want)
			}

			if got, want := vr.Entity(), tt.wantEntity; !reflect.DeepEqual(got, want) {
				t.Errorf("got entity %v, want %v", got, want)
			}
		})
	}
}

func TestNewVerifier(t *testing.T) { //nolint:maintidx
	emptyImage := loadContainer(t, filepath.Join(corpus, "empty.sif"))
	oneGroupImage := loadContainer(t, filepath.Join(corpus, "one-group.sif"))
	twoGroupImage := loadContainer(t, filepath.Join(corpus, "two-groups.sif"))

	sv := getTestVerifier(t, "ed25519-public.pem", crypto.Hash(0))

	kr := openpgp.EntityList{getTestEntity(t)}

	cb := func(_ VerifyResult) bool { return false }

	tests := []struct {
		name          string
		fi            *sif.FileImage
		opts          []VerifierOpt
		wantErr       error
		wantDSSE      decoder
		wantClearsign decoder
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
			name:       "OptVerifyWithVerifier",
			fi:         twoGroupImage,
			opts:       []VerifierOpt{OptVerifyWithVerifier(sv)},
			wantDSSE:   newDSSEDecoder(sv),
			wantGroups: []uint32{1, 2},
			wantTasks:  2,
		},
		{
			name:          "OptVerifyWithKeyRing",
			fi:            twoGroupImage,
			opts:          []VerifierOpt{OptVerifyWithKeyRing(kr)},
			wantClearsign: newClearsignDecoder(kr),
			wantGroups:    []uint32{1, 2},
			wantTasks:     2,
		},
		{
			name: "OptVerifyWithVerifierAndKeyRing",
			fi:   twoGroupImage,
			opts: []VerifierOpt{
				OptVerifyWithVerifier(sv),
				OptVerifyWithKeyRing(kr),
			},
			wantDSSE:      newDSSEDecoder(sv),
			wantClearsign: newClearsignDecoder(kr),
			wantGroups:    []uint32{1, 2},
			wantTasks:     2,
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
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(tt.fi, tt.opts...)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := v.f, tt.fi; got != want {
					t.Errorf("got FileImage %v, want %v", got, want)
				}

				if got, want := v.dsse, tt.wantDSSE; !reflect.DeepEqual(got, want) {
					t.Errorf("got DSSE decoder %+v, want %+v", got, want)
				}

				if got, want := v.cs, tt.wantClearsign; !reflect.DeepEqual(got, want) {
					t.Errorf("got clear-sign decoder %+v, want %+v", got, want)
				}

				if got, want := len(v.tasks), tt.wantTasks; got != want {
					t.Errorf("got %v tasks, want %v", got, want)
				}
			}
		})
	}
}

type mockVerifier struct {
	sigs    []sif.Descriptor
	sigsErr error

	verified  []sif.Descriptor
	e         *openpgp.Entity
	verifyErr error
}

func (v mockVerifier) signatures() ([]sif.Descriptor, error) {
	return v.sigs, v.sigsErr
}

func (v mockVerifier) verifySignature(_ context.Context, _ sif.Descriptor, _ decoder, vr *VerifyResult) error {
	vr.verified = v.verified
	vr.e = v.e
	return v.verifyErr
}

// getSignedDummy generates a dummy SIF container that contains a data object and one dummy
// signature per fingerprint.
func getSignedDummy(t *testing.T, fps ...[]byte) *sif.FileImage {
	t.Helper()

	di, err := sif.NewDescriptorInput(sif.DataGeneric, strings.NewReader("data"),
		sif.OptGroupID(1),
	)
	if err != nil {
		t.Fatal(err)
	}

	dis := []sif.DescriptorInput{di}

	for _, fp := range fps {
		di, err := sif.NewDescriptorInput(sif.DataSignature, strings.NewReader("sig"),
			sif.OptSignatureMetadata(crypto.SHA256, fp),
			sif.OptNoGroup(),
			sif.OptLinkedGroupID(1),
		)
		if err != nil {
			t.Fatal(err)
		}

		dis = append(dis, di)
	}

	var buf sif.Buffer

	fi, err := sif.CreateContainer(&buf,
		sif.OptCreateDeterministic(),
		sif.OptCreateWithDescriptors(dis...),
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := fi.UnloadContainer(); err != nil {
			t.Error(err)
		}
	})

	return fi
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

	fi := getSignedDummy(t, fp1, fp2)

	sigs, err := fi.GetDescriptors(sif.WithDataType(sif.DataSignature))
	if err != nil {
		t.Fatal(err)
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
				mockVerifier{sigsErr: io.EOF},
			},
			wantErr: io.EOF,
		},
		{
			name: "TwoTasksEOF",
			tasks: []verifyTask{
				mockVerifier{sigs: sigs[:1]},
				mockVerifier{sigsErr: io.EOF},
			},
			wantErr: io.EOF,
		},
		{
			name: "OneTaskOneFP",
			tasks: []verifyTask{
				mockVerifier{sigs: sigs[:1]},
			},
			wantFingerprints: [][]byte{fp1},
		},
		{
			name: "TwoTasksSameFP",
			tasks: []verifyTask{
				mockVerifier{sigs: sigs[:1]},
				mockVerifier{sigs: sigs[:1]},
			},
			wantFingerprints: [][]byte{fp1},
		},
		{
			name: "TwoTasksTwoFP",
			tasks: []verifyTask{
				mockVerifier{sigs: sigs[:1]},
				mockVerifier{sigs: sigs[1:]},
			},
			wantFingerprints: [][]byte{fp1, fp2},
		},
		{
			name: "KitchenSink",
			tasks: []verifyTask{
				mockVerifier{},
				mockVerifier{sigs: sigs[:1]},
				mockVerifier{sigs: sigs[1:]},
				mockVerifier{sigs: sigs},
			},
			wantFingerprints: [][]byte{fp1, fp2},
		},
	}

	for _, tt := range tests {
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

	fi := getSignedDummy(t, fp1, fp2)

	sigs, err := fi.GetDescriptors(sif.WithDataType(sif.DataSignature))
	if err != nil {
		t.Fatal(err)
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
				mockVerifier{sigsErr: io.EOF},
			},
			wantErr: io.EOF,
		},
		{
			name: "TwoTasksEOF",
			tasks: []verifyTask{
				mockVerifier{sigs: sigs[:1]},
				mockVerifier{sigsErr: io.EOF},
			},
			wantErr: io.EOF,
		},
		{
			name: "OneTaskNoFP",
			tasks: []verifyTask{
				mockVerifier{},
			},
		},
		{
			name: "OneTaskOneFP",
			tasks: []verifyTask{
				mockVerifier{sigs: sigs[:1]},
			},
			wantFingerprints: [][]byte{fp1},
		},
		{
			name: "TwoTasksSameFP",
			tasks: []verifyTask{
				mockVerifier{sigs: sigs[:1]},
				mockVerifier{sigs: sigs[:1]},
			},
			wantFingerprints: [][]byte{fp1},
		},
		{
			name: "TwoTasksTwoFP",
			tasks: []verifyTask{
				mockVerifier{sigs: sigs[:1]},
				mockVerifier{sigs: sigs[1:]},
			},
		},
		{
			name: "KitchenSink",
			tasks: []verifyTask{
				mockVerifier{},
				mockVerifier{sigs: sigs[:1]},
				mockVerifier{sigs: sigs[1:]},
				mockVerifier{sigs: sigs},
			},
		},
	}

	for _, tt := range tests {
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
	oneGroupImage := loadContainer(t, filepath.Join(corpus, "one-group.sif"))
	oneGroupSignedPGPImage := loadContainer(t, filepath.Join(corpus, "one-group-signed-pgp.sif"))
	oneGroupSignedDSSEImage := loadContainer(t, filepath.Join(corpus, "one-group-signed-dsse.sif"))

	verifiedDSSE, err := oneGroupSignedDSSEImage.GetDescriptors(sif.WithGroupID(1))
	if err != nil {
		t.Fatal(err)
	}

	sigDSSE, err := oneGroupSignedDSSEImage.GetDescriptor(sif.WithDataType(sif.DataSignature))
	if err != nil {
		t.Fatal(err)
	}

	verifiedPGP, err := oneGroupSignedPGPImage.GetDescriptors(sif.WithGroupID(1))
	if err != nil {
		t.Fatal(err)
	}

	sigPGP, err := oneGroupSignedPGPImage.GetDescriptor(sif.WithDataType(sif.DataSignature))
	if err != nil {
		t.Fatal(err)
	}

	ed25519 := getTestVerifier(t, "ed25519-public.pem", crypto.Hash(0))

	e := getTestEntity(t)

	kr := openpgp.EntityList{e}

	tests := []struct {
		name            string
		f               *sif.FileImage
		opts            []VerifierOpt
		testCallback    bool
		ignoreError     bool
		wantCBSignature sif.Descriptor
		wantCBVerified  []sif.Descriptor
		wantCBKeys      []crypto.PublicKey
		wantCBEntity    *openpgp.Entity
		wantCBErr       error
		wantErr         error
	}{
		{
			name:    "SignatureNotFound",
			f:       oneGroupImage,
			wantErr: &SignatureNotFoundError{},
		},
		{
			name: "NoKeyMaterialDSSE",
			f:    oneGroupSignedDSSEImage,
			opts: []VerifierOpt{
				OptVerifyWithKeyRing(kr),
			},
			wantErr: errNoKeyMaterialDSSE,
		},
		{
			name: "NoKeyMaterialPGP",
			f:    oneGroupSignedPGPImage,
			opts: []VerifierOpt{
				OptVerifyWithVerifier(ed25519),
			},
			wantErr: errNoKeyMaterialPGP,
		},
		{
			name: "SignatureNotValidErrorDSSE",
			f:    oneGroupSignedDSSEImage,
			opts: []VerifierOpt{
				OptVerifyWithVerifier(
					getTestVerifier(t, "ecdsa-public.pem", crypto.SHA256), // Not signed with ECDSA.
				),
			},
			wantErr: &SignatureNotValidError{ID: 3},
		},
		{
			name: "SignatureNotValidErrorPGP",
			f:    oneGroupSignedPGPImage,
			opts: []VerifierOpt{
				OptVerifyWithKeyRing(openpgp.EntityList{}),
			},
			wantErr: &SignatureNotValidError{ID: 3},
		},
		{
			name: "OneGroupSignedDSSE",
			f:    oneGroupSignedDSSEImage,
			opts: []VerifierOpt{
				OptVerifyWithVerifier(ed25519),
			},
		},
		{
			name: "OneGroupSignedPGP",
			f:    oneGroupSignedPGPImage,
			opts: []VerifierOpt{
				OptVerifyWithKeyRing(kr),
			},
		},
		{
			name: "OneGroupSignedDSSEWithCallback",
			f:    oneGroupSignedDSSEImage,
			opts: []VerifierOpt{
				OptVerifyWithVerifier(ed25519),
			},
			testCallback:    true,
			wantCBSignature: sigDSSE,
			wantCBVerified:  verifiedDSSE,
			wantCBKeys: []crypto.PublicKey{
				getTestPublicKey(t, "ed25519-public.pem"),
			},
			wantCBEntity: nil,
		},
		{
			name: "OneGroupSignedPGPWithCallback",
			f:    oneGroupSignedPGPImage,
			opts: []VerifierOpt{
				OptVerifyWithKeyRing(kr),
			},
			testCallback:    true,
			wantCBSignature: sigPGP,
			wantCBVerified:  verifiedPGP,
			wantCBEntity:    e,
		},
		{
			name: "OneGroupSignedPGPWithCallbackIgnoreError",
			f:    oneGroupSignedPGPImage,
			opts: []VerifierOpt{
				OptVerifyWithKeyRing(openpgp.EntityList{}),
			},
			testCallback:    true,
			ignoreError:     true,
			wantCBSignature: sigPGP,
			wantCBEntity:    nil,
			wantCBErr:       &SignatureNotValidError{ID: 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var vr VerifyResult

			opts := tt.opts
			if tt.testCallback {
				opts = append(opts, OptVerifyCallback(func(r VerifyResult) bool {
					vr = r
					return tt.ignoreError
				}))
			}

			v, err := NewVerifier(tt.f, opts...)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := v.Verify(), tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if tt.testCallback {
				if got, want := vr.Signature(), tt.wantCBSignature; got != want {
					t.Errorf("got signature %v, want %v", got, want)
				}

				if got, want := vr.Verified(), tt.wantCBVerified; !reflect.DeepEqual(got, want) {
					t.Errorf("got verified %v, want %v", got, want)
				}

				if got, want := vr.Keys(), tt.wantCBKeys; !reflect.DeepEqual(got, want) {
					t.Errorf("got keys %v, want %v", got, want)
				}

				if got, want := vr.Entity(), tt.wantCBEntity; got != want {
					t.Errorf("got entity %v, want %v", got, want)
				}

				if got, want := vr.Error(), tt.wantCBErr; !errors.Is(got, want) {
					t.Errorf("got error %v, want %v", got, want)
				}
			}
		})
	}
}
