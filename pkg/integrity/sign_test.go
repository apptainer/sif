// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/apptainer/sif/v2/pkg/sif"
)

func TestOptSignGroupObjects(t *testing.T) {
	twoGroupImage := loadContainer(t, filepath.Join(corpus, "two-groups.sif"))

	tests := []struct {
		name    string
		groupID uint32
		ids     []uint32
		wantErr error
	}{
		{
			name:    "NoObjectsSpecified",
			ids:     []uint32{},
			wantErr: errNoObjectsSpecified,
		},
		{
			name:    "InvalidObjectID",
			ids:     []uint32{0},
			wantErr: sif.ErrInvalidObjectID,
		},
		{
			name:    "UnexpectedGroupID",
			groupID: 1,
			ids:     []uint32{3},
			wantErr: errUnexpectedGroupID,
		},
		{
			name:    "ObjectNotFound",
			groupID: 1,
			ids:     []uint32{4},
			wantErr: sif.ErrObjectNotFound,
		},
		{
			name:    "Object1",
			groupID: 1,
			ids:     []uint32{1},
		},
		{
			name:    "Object2",
			groupID: 1,
			ids:     []uint32{2},
		},
		{
			name:    "Object3",
			groupID: 2,
			ids:     []uint32{3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gs := groupSigner{f: twoGroupImage, id: tt.groupID}

			err := optSignGroupObjects(tt.ids...)(&gs)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				var got []uint32
				for _, od := range gs.ods {
					got = append(got, od.ID())
				}
				if want := tt.ids; !slices.Equal(got, want) {
					t.Errorf("got objects %v, want %v", got, want)
				}
			}
		})
	}
}

func TestNewGroupSigner(t *testing.T) {
	emptyImage := loadContainer(t, filepath.Join(corpus, "empty.sif"))
	twoGroupImage := loadContainer(t, filepath.Join(corpus, "two-groups.sif"))

	tests := []struct {
		name        string
		fi          *sif.FileImage
		groupID     uint32
		opts        []groupSignerOpt
		wantErr     error
		wantObjects []uint32
		wantMDHash  crypto.Hash
		wantFP      []byte
	}{
		{
			name:    "InvalidGroupID",
			fi:      emptyImage,
			groupID: 0,
			wantErr: sif.ErrInvalidGroupID,
		},
		{
			name:    "NoObjects",
			fi:      emptyImage,
			groupID: 1,
			wantErr: sif.ErrNoObjects,
		},
		{
			name:    "NoObjectsSpecified",
			fi:      emptyImage,
			groupID: 1,
			opts:    []groupSignerOpt{optSignGroupObjects()},
			wantErr: errNoObjectsSpecified,
		},
		{
			name:    "GroupNotFound",
			fi:      twoGroupImage,
			groupID: 3,
			wantErr: errGroupNotFound,
		},
		{
			name:        "Group1",
			fi:          twoGroupImage,
			groupID:     1,
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA256,
		},
		{
			name:        "Group2",
			fi:          twoGroupImage,
			groupID:     2,
			wantObjects: []uint32{3},
			wantMDHash:  crypto.SHA256,
		},
		{
			name:        "OptSignGroupObject1",
			fi:          twoGroupImage,
			groupID:     1,
			opts:        []groupSignerOpt{optSignGroupObjects(1)},
			wantObjects: []uint32{1},
			wantMDHash:  crypto.SHA256,
		},
		{
			name:        "OptSignGroupObject2",
			fi:          twoGroupImage,
			groupID:     1,
			opts:        []groupSignerOpt{optSignGroupObjects(2)},
			wantObjects: []uint32{2},
			wantMDHash:  crypto.SHA256,
		},
		{
			name:        "OptSignGroupObject3",
			fi:          twoGroupImage,
			groupID:     2,
			opts:        []groupSignerOpt{optSignGroupObjects(3)},
			wantObjects: []uint32{3},
			wantMDHash:  crypto.SHA256,
		},
		{
			name:        "OptSignGroupMetadataHash",
			fi:          twoGroupImage,
			groupID:     1,
			opts:        []groupSignerOpt{optSignGroupMetadataHash(crypto.SHA384)},
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA384,
		},
		{
			name:    "OptSignGroupMetadataHash",
			fi:      twoGroupImage,
			groupID: 1,
			opts: []groupSignerOpt{
				optSignGroupFingerprint([]byte{
					0x12, 0x04, 0x5c, 0x8c, 0x0b, 0x10, 0x04, 0xd0, 0x58, 0xde,
					0x4b, 0xed, 0xa2, 0x0c, 0x27, 0xee, 0x7f, 0xf7, 0xba, 0x84,
				}),
			},
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA256,
			wantFP: []byte{
				0x12, 0x04, 0x5c, 0x8c, 0x0b, 0x10, 0x04, 0xd0, 0x58, 0xde,
				0x4b, 0xed, 0xa2, 0x0c, 0x27, 0xee, 0x7f, 0xf7, 0xba, 0x84,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			en := newClearsignEncoder(getTestEntity(t), fixedTime)

			s, err := newGroupSigner(en, tt.fi, tt.groupID, tt.opts...)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := s.en, en; got != want {
					t.Errorf("got encoder %v, want %v", got, want)
				}

				if got, want := s.f, tt.fi; got != want {
					t.Errorf("got FileImage %v, want %v", got, want)
				}

				if got, want := s.id, tt.groupID; got != want {
					t.Errorf("got group ID %v, want %v", got, want)
				}

				var got []uint32
				for _, od := range s.ods {
					got = append(got, od.ID())
				}
				if want := tt.wantObjects; !slices.Equal(got, want) {
					t.Errorf("got objects %v, want %v", got, want)
				}

				if got, want := s.mdHash, tt.wantMDHash; got != want {
					t.Errorf("got metadata hash %v, want %v", got, want)
				}

				if got, want := s.fp, tt.wantFP; !bytes.Equal(got, want) {
					t.Errorf("got fingerprint %v, want %v", got, want)
				}
			}
		})
	}
}

func TestGroupSigner_Sign(t *testing.T) {
	twoGroups := loadContainer(t, filepath.Join(corpus, "two-groups.sif"))

	d1, err := twoGroups.GetDescriptor(sif.WithID(1))
	if err != nil {
		t.Fatal(err)
	}

	d2, err := twoGroups.GetDescriptor(sif.WithID(2))
	if err != nil {
		t.Fatal(err)
	}

	d3, err := twoGroups.GetDescriptor(sif.WithID(3))
	if err != nil {
		t.Fatal(err)
	}

	e := getTestEntity(t)
	clearsign := newClearsignEncoder(e, fixedTime)

	encrypted := getTestEntity(t)
	encrypted.PrivateKey.Encrypted = true

	clearsignEncrypted := newClearsignEncoder(encrypted, fixedTime)

	tests := []struct {
		name    string
		gs      groupSigner
		wantErr bool
	}{
		{
			name: "HashUnavailable",
			gs: groupSigner{
				en:     clearsign,
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d1},
				mdHash: crypto.MD4,
				fp:     e.PrimaryKey.Fingerprint,
			},
			wantErr: true,
		},
		{
			name: "EncryptedKey",
			gs: groupSigner{
				en:     clearsignEncrypted,
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d1},
				mdHash: crypto.SHA256,
				fp:     encrypted.PrimaryKey.Fingerprint,
			},
			wantErr: true,
		},
		{
			name: "Object1",
			gs: groupSigner{
				en:     clearsign,
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d1},
				mdHash: crypto.SHA256,
				fp:     e.PrimaryKey.Fingerprint,
			},
		},
		{
			name: "Object2",
			gs: groupSigner{
				en:     clearsign,
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d2},
				mdHash: crypto.SHA256,
				fp:     e.PrimaryKey.Fingerprint,
			},
		},
		{
			name: "Group1",
			gs: groupSigner{
				en:     clearsign,
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d1, d2},
				mdHash: crypto.SHA256,
				fp:     e.PrimaryKey.Fingerprint,
			},
		},
		{
			name: "Group2",
			gs: groupSigner{
				en:     clearsign,
				f:      twoGroups,
				id:     2,
				ods:    []sif.Descriptor{d3},
				mdHash: crypto.SHA256,
				fp:     e.PrimaryKey.Fingerprint,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			di, err := tt.gs.sign(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("got error %v, want %v", err, tt.wantErr)
			}

			if err == nil {
				var buf sif.Buffer

				fi, err := sif.CreateContainer(&buf,
					sif.OptCreateDeterministic(),
					sif.OptCreateWithDescriptors(di),
				)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := fi.UnloadContainer(); err != nil {
						t.Error(err)
					}
				})

				d, err := fi.GetDescriptor(sif.WithDataType(sif.DataSignature))
				if err != nil {
					t.Fatal(err)
				}

				if got, want := d.GroupID(), uint32(0); got != want {
					t.Errorf("got group ID %v, want %v", got, want)
				}

				id, isGroup := d.LinkedID()
				if got, want := id, tt.gs.id; got != want {
					t.Errorf("got linked ID %v, want %v", got, want)
				}
				if !isGroup {
					t.Error("got linked object, want linked group")
				}

				ht, fp, err := d.SignatureMetadata()
				if err != nil {
					t.Fatal(err)
				}
				if got, want := ht, crypto.SHA256; got != want {
					t.Errorf("got hash %v, want %v", got, want)
				}
				if got, want := fp, tt.gs.fp; !bytes.Equal(got, want) {
					t.Errorf("got fingerprint %v, want %v", got, want)
				}
			}
		})
	}
}

func TestNewSigner(t *testing.T) {
	emptyImage := loadContainer(t, filepath.Join(corpus, "empty.sif"))
	oneGroupImage := loadContainer(t, filepath.Join(corpus, "one-group.sif"))
	twoGroupImage := loadContainer(t, filepath.Join(corpus, "two-groups.sif"))

	e := getTestEntity(t)

	tests := []struct {
		name             string
		fi               *sif.FileImage
		opts             []SignerOpt
		wantErr          error
		wantGroupObjects map[uint32][]uint32
		wantEntity       *openpgp.Entity
	}{
		{
			name: "NilFileImage",
			fi:   nil,
			opts: []SignerOpt{
				OptSignWithEntity(e),
			},
			wantErr: errNilFileImage,
		},
		{
			name: "NoGroupsFound",
			fi:   emptyImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
			},
			wantErr: errNoGroupsFound,
		},
		{
			name: "InvalidGroupID",
			fi:   emptyImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignGroup(0),
			},
			wantErr: sif.ErrInvalidGroupID,
		},
		{
			name: "NoObjectsSpecified",
			fi:   emptyImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignObjects(),
			},
			wantErr: errNoObjectsSpecified,
		},
		{
			name: "NoObjects",
			fi:   emptyImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignObjects(1),
			},
			wantErr: sif.ErrNoObjects,
		},
		{
			name: "InvalidObjectID",
			fi:   oneGroupImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignObjects(0),
			},
			wantErr: sif.ErrInvalidObjectID,
		},
		{
			name: "OneGroupDefaultObjects",
			fi:   oneGroupImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
			},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}},
		},
		{
			name: "TwoGroupDefaultObjects",
			fi:   twoGroupImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
			},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}, 2: {3}},
		},
		{
			name: "OptSignGroup1",
			fi:   twoGroupImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignGroup(1),
			},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}},
		},
		{
			name: "OptSignGroup2",
			fi:   twoGroupImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignGroup(2),
			},
			wantGroupObjects: map[uint32][]uint32{2: {3}},
		},
		{
			name: "OptSignObject1",
			fi:   twoGroupImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignObjects(1),
			},
			wantGroupObjects: map[uint32][]uint32{1: {1}},
		},
		{
			name: "OptSignObject2",
			fi:   twoGroupImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignObjects(2),
			},
			wantGroupObjects: map[uint32][]uint32{1: {2}},
		},
		{
			name: "OptSignObject3",
			fi:   twoGroupImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignObjects(3),
			},
			wantGroupObjects: map[uint32][]uint32{2: {3}},
		},
		{
			name: "OptSignObjects",
			fi:   twoGroupImage,
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignObjects(1, 2, 3),
			},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}, 2: {3}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewSigner(tt.fi, tt.opts...)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := s.f, tt.fi; got != want {
					t.Errorf("got FileImage %v, want %v", got, want)
				}

				if got, want := len(s.signers), len(tt.wantGroupObjects); got != want {
					t.Errorf("got %v signers, want %v", got, want)
				}

				for _, signer := range s.signers {
					groupID := signer.id

					if want, ok := tt.wantGroupObjects[groupID]; !ok {
						t.Errorf("unexpected signer for group ID %v", groupID)
					} else {
						var got []uint32
						for _, od := range signer.ods {
							got = append(got, od.ID())
						}

						if !slices.Equal(got, want) {
							t.Errorf("got objects %v, want %v", got, want)
						}
					}
				}
			}
		})
	}
}

//nolint:maintidx
func TestSigner_Sign(t *testing.T) {
	e := getTestEntity(t)

	encrypted := getTestEntity(t)
	if err := encrypted.PrivateKey.Encrypt([]byte("blah")); err != nil {
		t.Fatal(err)
	}

	ss := getTestSigner(t, "ed25519-private.pem", crypto.Hash(0))
	sv := getTestVerifier(t, "ed25519-public.pem", crypto.Hash(0))

	tests := []struct {
		name       string
		inputFile  string
		signOpts   []SignerOpt
		verifyOpts []VerifierOpt
		wantErr    bool
	}{
		{
			name:      "EncryptedKey",
			inputFile: "one-group.sif",
			signOpts:  []SignerOpt{OptSignWithEntity(encrypted)},
			wantErr:   true,
		},
		{
			name:      "OneGroupDSSE",
			inputFile: "one-group.sif",
			signOpts: []SignerOpt{
				OptSignWithSigner(ss),
				OptSignWithTime(fixedTime),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithVerifier(sv),
			},
		},
		{
			name:      "OneGroupPGP",
			inputFile: "one-group.sif",
			signOpts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithKeyRing(openpgp.EntityList{e}),
			},
		},
		{
			name:      "TwoGroupsDSSE",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithSigner(ss),
				OptSignWithTime(fixedTime),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithVerifier(sv),
			},
		},
		{
			name:      "TwoGroupsPGP",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithKeyRing(openpgp.EntityList{e}),
			},
		},
		{
			name:      "OptSignGroup1DSSE",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithSigner(ss),
				OptSignWithTime(fixedTime),
				OptSignGroup(1),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithVerifier(sv),
				OptVerifyGroup(1),
			},
		},
		{
			name:      "OptSignGroup1PGP",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignGroup(1),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithKeyRing(openpgp.EntityList{e}),
				OptVerifyGroup(1),
			},
		},
		{
			name:      "OptSignGroup2DSSE",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithSigner(ss),
				OptSignWithTime(fixedTime),
				OptSignGroup(2),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithVerifier(sv),
				OptVerifyGroup(2),
			},
		},
		{
			name:      "OptSignGroup2PGP",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignGroup(2),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithKeyRing(openpgp.EntityList{e}),
				OptVerifyGroup(2),
			},
		},
		{
			name:      "OptSignObject1DSSE",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithSigner(ss),
				OptSignWithTime(fixedTime),
				OptSignObjects(1),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithVerifier(sv),
				OptVerifyObject(1),
			},
		},
		{
			name:      "OptSignObject1PGP",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignObjects(1),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithKeyRing(openpgp.EntityList{e}),
				OptVerifyObject(1),
			},
		},
		{
			name:      "OptSignObject2DSSE",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithSigner(ss),
				OptSignWithTime(fixedTime),
				OptSignObjects(2),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithVerifier(sv),
				OptVerifyObject(2),
			},
		},
		{
			name:      "OptSignObject2PGP",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignObjects(2),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithKeyRing(openpgp.EntityList{e}),
				OptVerifyObject(2),
			},
		},
		{
			name:      "OptSignObject3DSSE",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithSigner(ss),
				OptSignWithTime(fixedTime),
				OptSignObjects(3),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithVerifier(sv),
				OptVerifyObject(3),
			},
		},
		{
			name:      "OptSignObject3PGP",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignObjects(3),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithKeyRing(openpgp.EntityList{e}),
				OptVerifyObject(3),
			},
		},
		{
			name:      "OptSignObjectsDSSE",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithSigner(ss),
				OptSignWithTime(fixedTime),
				OptSignObjects(1, 2, 3),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithVerifier(sv),
				OptVerifyObject(1),
				OptVerifyObject(2),
				OptVerifyObject(3),
			},
		},
		{
			name:      "OptSignObjectsPGP",
			inputFile: "two-groups.sif",
			signOpts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignObjects(1, 2, 3),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithKeyRing(openpgp.EntityList{e}),
				OptVerifyObject(1),
				OptVerifyObject(2),
				OptVerifyObject(3),
			},
		},
		{
			name:      "OptSignDeterministicDSSE",
			inputFile: "one-group.sif",
			signOpts: []SignerOpt{
				OptSignWithSigner(ss),
				OptSignWithTime(fixedTime),
				OptSignDeterministic(),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithVerifier(sv),
			},
		},
		{
			name:      "OptSignDeterministicPGP",
			inputFile: "one-group.sif",
			signOpts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignDeterministic(),
			},
			verifyOpts: []VerifierOpt{
				OptVerifyWithKeyRing(openpgp.EntityList{e}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(corpus, tt.inputFile))
			if err != nil {
				t.Fatal(err)
			}

			buf := sif.NewBuffer(b)

			f, err := sif.LoadContainer(buf)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := f.UnloadContainer(); err != nil {
					t.Error(err)
				}
			})

			s, err := NewSigner(f, tt.signOpts...)
			if err != nil {
				t.Fatal(err)
			}

			if err := s.Sign(); (err != nil) != tt.wantErr {
				t.Fatalf("got error %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				v, err := NewVerifier(f, tt.verifyOpts...)
				if err != nil {
					t.Fatal(err)
				}

				if err := v.Verify(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
