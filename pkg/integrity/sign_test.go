// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"crypto"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/hpcng/sif/v2/pkg/sif"
	"github.com/sebdah/goldie/v2"
)

func TestOptSignGroupObjects(t *testing.T) {
	twoGroupImage, err := sif.LoadContainer(filepath.Join("testdata", "images", "two-groups.sif"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer twoGroupImage.UnloadContainer() // nolint:errcheck

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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			gs := groupSigner{f: &twoGroupImage, id: tt.groupID}

			err := optSignGroupObjects(tt.ids...)(&gs)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				var got []uint32
				for _, od := range gs.ods {
					got = append(got, od.GetID())
				}
				if want := tt.ids; !reflect.DeepEqual(got, want) {
					t.Errorf("got objects %v, want %v", got, want)
				}
			}
		})
	}
}

func TestNewGroupSigner(t *testing.T) {
	emptyImage, err := sif.LoadContainer(filepath.Join("testdata", "images", "empty.sif"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer emptyImage.UnloadContainer() // nolint:errcheck

	twoGroupImage, err := sif.LoadContainer(filepath.Join("testdata", "images", "two-groups.sif"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer twoGroupImage.UnloadContainer() // nolint:errcheck

	tests := []struct {
		name        string
		fi          *sif.FileImage
		groupID     uint32
		opts        []groupSignerOpt
		wantErr     error
		wantObjects []uint32
		wantMDHash  crypto.Hash
		wantSigHash sif.Hashtype
	}{
		{
			name:    "InvalidGroupID",
			fi:      &emptyImage,
			groupID: 0,
			wantErr: sif.ErrInvalidGroupID,
		},
		{
			name:    "GroupNotFound",
			fi:      &emptyImage,
			groupID: 1,
			wantErr: errGroupNotFound,
		},
		{
			name:    "NoObjectsSpecified",
			fi:      &emptyImage,
			groupID: 1,
			opts:    []groupSignerOpt{optSignGroupObjects()},
			wantErr: errNoObjectsSpecified,
		},
		{
			name:        "Group1",
			fi:          &twoGroupImage,
			groupID:     1,
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA256,
			wantSigHash: sif.HashSHA256,
		},
		{
			name:        "Group2",
			fi:          &twoGroupImage,
			groupID:     2,
			wantObjects: []uint32{3},
			wantMDHash:  crypto.SHA256,
			wantSigHash: sif.HashSHA256,
		},
		{
			name:        "OptSignGroupObject1",
			fi:          &twoGroupImage,
			groupID:     1,
			opts:        []groupSignerOpt{optSignGroupObjects(1)},
			wantObjects: []uint32{1},
			wantMDHash:  crypto.SHA256,
			wantSigHash: sif.HashSHA256,
		},
		{
			name:        "OptSignGroupObject2",
			fi:          &twoGroupImage,
			groupID:     1,
			opts:        []groupSignerOpt{optSignGroupObjects(2)},
			wantObjects: []uint32{2},
			wantMDHash:  crypto.SHA256,
			wantSigHash: sif.HashSHA256,
		},
		{
			name:        "OptSignGroupObject3",
			fi:          &twoGroupImage,
			groupID:     2,
			opts:        []groupSignerOpt{optSignGroupObjects(3)},
			wantObjects: []uint32{3},
			wantMDHash:  crypto.SHA256,
			wantSigHash: sif.HashSHA256,
		},
		{
			name:        "OptSignGroupMetadataHash",
			fi:          &twoGroupImage,
			groupID:     1,
			opts:        []groupSignerOpt{optSignGroupMetadataHash(crypto.SHA1)},
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA1,
			wantSigHash: sif.HashSHA256,
		},
		{
			name:    "OptSignGroupSignatureConfigSHA256",
			fi:      &twoGroupImage,
			groupID: 1,
			opts: []groupSignerOpt{optSignGroupSignatureConfig(&packet.Config{
				DefaultHash: crypto.SHA256,
			})},
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA256,
			wantSigHash: sif.HashSHA256,
		},
		{
			name:    "OptSignGroupSignatureConfigSHA384",
			fi:      &twoGroupImage,
			groupID: 1,
			opts: []groupSignerOpt{optSignGroupSignatureConfig(&packet.Config{
				DefaultHash: crypto.SHA384,
			})},
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA256,
			wantSigHash: sif.HashSHA384,
		},
		{
			name:    "OptSignGroupSignatureConfigSHA512",
			fi:      &twoGroupImage,
			groupID: 1,
			opts: []groupSignerOpt{optSignGroupSignatureConfig(&packet.Config{
				DefaultHash: crypto.SHA512,
			})},
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA256,
			wantSigHash: sif.HashSHA512,
		},
		{
			name:    "OptSignGroupSignatureConfigBLAKE2s_256",
			fi:      &twoGroupImage,
			groupID: 1,
			opts: []groupSignerOpt{optSignGroupSignatureConfig(&packet.Config{
				DefaultHash: crypto.BLAKE2s_256,
			})},
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA256,
			wantSigHash: sif.HashBLAKE2S,
		},
		{
			name:    "OptSignGroupSignatureConfigBLAKE2b_256",
			fi:      &twoGroupImage,
			groupID: 1,
			opts: []groupSignerOpt{optSignGroupSignatureConfig(&packet.Config{
				DefaultHash: crypto.BLAKE2b_256,
			})},
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA256,
			wantSigHash: sif.HashBLAKE2B,
		},
		{
			name:    "OptSignGroupSignatureConfigBLAKE2b_384",
			fi:      &twoGroupImage,
			groupID: 1,
			opts: []groupSignerOpt{optSignGroupSignatureConfig(&packet.Config{
				DefaultHash: crypto.BLAKE2b_384,
			})},
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA256,
			wantSigHash: sif.HashBLAKE2B,
		},
		{
			name:    "OptSignGroupSignatureConfigBLAKE2b_512",
			fi:      &twoGroupImage,
			groupID: 1,
			opts: []groupSignerOpt{optSignGroupSignatureConfig(&packet.Config{
				DefaultHash: crypto.BLAKE2b_512,
			})},
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA256,
			wantSigHash: sif.HashBLAKE2B,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			s, err := newGroupSigner(tt.fi, tt.groupID, tt.opts...)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := s.f, tt.fi; got != want {
					t.Errorf("got FileImage %v, want %v", got, want)
				}

				if got, want := s.id, tt.groupID; got != want {
					t.Errorf("got group ID %v, want %v", got, want)
				}

				var got []uint32
				for _, od := range s.ods {
					got = append(got, od.GetID())
				}
				if want := tt.wantObjects; !reflect.DeepEqual(got, want) {
					t.Errorf("got objects %v, want %v", got, want)
				}

				if got, want := s.mdHash, tt.wantMDHash; got != want {
					t.Errorf("got metadata hash %v, want %v", got, want)
				}

				if got, want := s.sigHash, tt.wantSigHash; got != want {
					t.Errorf("got sig hash %v, want %v", got, want)
				}
			}
		})
	}
}

func TestGroupSigner_SignWithEntity(t *testing.T) {
	twoGroups, err := sif.LoadContainer(filepath.Join("testdata", "images", "two-groups.sif"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer twoGroups.UnloadContainer() // nolint:errcheck

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

	encrypted := getTestEntity(t)
	encrypted.PrivateKey.Encrypted = true

	// Use a fixed time to ensure repeatable results.
	config := packet.Config{Time: fixedTime}

	tests := []struct {
		name    string
		gs      groupSigner
		e       *openpgp.Entity
		wantErr bool
	}{
		{
			name: "HashUnavailable",
			gs: groupSigner{
				f:         &twoGroups,
				id:        1,
				ods:       []sif.Descriptor{d1},
				mdHash:    crypto.MD4,
				sigConfig: &config,
			},
			e:       e,
			wantErr: true,
		},
		{
			name: "EncryptedKey",
			gs: groupSigner{
				f:         &twoGroups,
				id:        1,
				ods:       []sif.Descriptor{d1},
				mdHash:    crypto.SHA1,
				sigConfig: &config,
			},
			e:       encrypted,
			wantErr: true,
		},
		{
			name: "Object1",
			gs: groupSigner{
				f:         &twoGroups,
				id:        1,
				ods:       []sif.Descriptor{d1},
				mdHash:    crypto.SHA1,
				sigConfig: &config,
			},
			e: e,
		},
		{
			name: "Object2",
			gs: groupSigner{
				f:         &twoGroups,
				id:        1,
				ods:       []sif.Descriptor{d2},
				mdHash:    crypto.SHA1,
				sigConfig: &config,
			},
			e: e,
		},
		{
			name: "Group1",
			gs: groupSigner{
				f:         &twoGroups,
				id:        1,
				ods:       []sif.Descriptor{d1, d2},
				mdHash:    crypto.SHA1,
				sigConfig: &config,
			},
			e: e,
		},
		{
			name: "Group2",
			gs: groupSigner{
				f:         &twoGroups,
				id:        2,
				ods:       []sif.Descriptor{d3},
				mdHash:    crypto.SHA1,
				sigConfig: &config,
			},
			e: e,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			di, err := tt.gs.signWithEntity(tt.e)
			if (err != nil) != tt.wantErr {
				t.Fatalf("got error %v, want %v", err, tt.wantErr)
			}

			if err == nil {
				if got, want := di.Datatype, sif.DataSignature; got != want {
					t.Errorf("got data type %v, want %v", got, want)
				}

				if got, want := di.Groupid, uint32(sif.DescrUnusedGroup); got != want {
					t.Errorf("got group ID %v, want %v", got, want)
				}

				if got, want := di.Link, sif.DescrGroupMask|tt.gs.id; got != want {
					t.Errorf("got link %v, want %v", got, want)
				}

				b := make([]byte, di.Size)
				if _, err := io.ReadFull(di.Fp, b); err != nil {
					t.Fatal(err)
				}
				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b)
			}
		})
	}
}

func TestOptSignGroup(t *testing.T) {
	oneGroup, err := sif.LoadContainer(filepath.Join("testdata", "images", "one-group.sif"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer oneGroup.UnloadContainer() // nolint:errcheck

	tests := []struct {
		name    string
		gid     uint32
		wantErr error
	}{
		{
			name:    "InvalidGroupID",
			gid:     0,
			wantErr: sif.ErrInvalidGroupID,
		},
		{
			name: "Group1",
			gid:  1,
		},
		{
			name:    "GroupNotFound",
			gid:     2,
			wantErr: errGroupNotFound,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			s := Signer{f: &oneGroup}

			err := OptSignGroup(tt.gid)(&s)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := len(s.signers), 1; got != want {
					t.Fatalf("got %v signers, want %v", got, want)
				}

				if got, want := s.signers[0].id, tt.gid; got != want {
					t.Errorf("got group ID %v, want %v", got, want)
				}
			}
		})
	}
}

func TestOptSignObjects(t *testing.T) {
	tests := []struct {
		name             string
		inputFileName    string
		ids              []uint32
		wantErr          error
		wantGroupObjects map[uint32][]uint32
	}{
		{
			name:          "NoObjectsSpecified",
			inputFileName: "empty.sif",
			ids:           []uint32{},
			wantErr:       errNoObjectsSpecified,
		},
		{
			name:          "InvalidObjectID",
			inputFileName: "empty.sif",
			ids:           []uint32{0},
			wantErr:       sif.ErrInvalidObjectID,
		},
		{
			name:          "ObjectNotFound",
			inputFileName: "empty.sif",
			ids:           []uint32{1},
			wantErr:       sif.ErrObjectNotFound,
		},
		{
			name:             "Duplicates",
			inputFileName:    "one-group.sif",
			ids:              []uint32{1, 1},
			wantGroupObjects: map[uint32][]uint32{1: {1}},
		},
		{
			name:             "Object1",
			inputFileName:    "one-group.sif",
			ids:              []uint32{1},
			wantGroupObjects: map[uint32][]uint32{1: {1}},
		},
		{
			name:             "Object2",
			inputFileName:    "one-group.sif",
			ids:              []uint32{2},
			wantGroupObjects: map[uint32][]uint32{1: {2}},
		},
		{
			name:             "Object3",
			inputFileName:    "two-groups.sif",
			ids:              []uint32{3},
			wantGroupObjects: map[uint32][]uint32{2: {3}},
		},
		{
			name:             "AllObjects",
			inputFileName:    "two-groups.sif",
			ids:              []uint32{1, 2, 3},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}, 2: {3}},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			f, err := sif.LoadContainer(filepath.Join("testdata", "images", tt.inputFileName), true)
			if err != nil {
				t.Fatal(err)
			}
			defer f.UnloadContainer() //nolint:errcheck

			s := Signer{f: &f}

			err = OptSignObjects(tt.ids...)(&s)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				for _, gs := range s.signers {
					if want, ok := tt.wantGroupObjects[gs.id]; !ok {
						t.Fatalf("unexpected signer for group ID %v", gs.id)
					} else {
						var got []uint32
						for _, od := range gs.ods {
							got = append(got, od.GetID())
						}

						if !reflect.DeepEqual(got, want) {
							t.Errorf("got objects %v, want %v", got, want)
						}
					}
				}
			}
		})
	}
}

func TestNewSigner(t *testing.T) {
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
			name:    "NilFileImage",
			fi:      nil,
			wantErr: errNilFileImage,
		},
		{
			name:    "NoGroupsFound",
			fi:      &emptyImage,
			wantErr: errNoGroupsFound,
		},
		{
			name:    "InvalidGroupID",
			fi:      &emptyImage,
			opts:    []SignerOpt{OptSignGroup(0)},
			wantErr: sif.ErrInvalidGroupID,
		},
		{
			name:    "NoObjectsSpecified",
			fi:      &emptyImage,
			opts:    []SignerOpt{OptSignObjects()},
			wantErr: errNoObjectsSpecified,
		},
		{
			name:    "InvalidObjectID",
			fi:      &emptyImage,
			opts:    []SignerOpt{OptSignObjects(0)},
			wantErr: sif.ErrInvalidObjectID,
		},
		{
			name:             "OneGroupDefaultObjects",
			fi:               &oneGroupImage,
			opts:             []SignerOpt{},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}},
		},
		{
			name:             "TwoGroupDefaultObjects",
			fi:               &twoGroupImage,
			opts:             []SignerOpt{},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}, 2: {3}},
		},
		{
			name:             "OptSignWithEntity",
			fi:               &twoGroupImage,
			opts:             []SignerOpt{OptSignWithEntity(e)},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}, 2: {3}},
			wantEntity:       e,
		},
		{
			name:             "OptSignGroup1",
			fi:               &twoGroupImage,
			opts:             []SignerOpt{OptSignGroup(1)},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}},
		},
		{
			name:             "OptSignGroup2",
			fi:               &twoGroupImage,
			opts:             []SignerOpt{OptSignGroup(2)},
			wantGroupObjects: map[uint32][]uint32{2: {3}},
		},
		{
			name:             "OptSignObject1",
			fi:               &twoGroupImage,
			opts:             []SignerOpt{OptSignObjects(1)},
			wantGroupObjects: map[uint32][]uint32{1: {1}},
		},
		{
			name:             "OptSignObject2",
			fi:               &twoGroupImage,
			opts:             []SignerOpt{OptSignObjects(2)},
			wantGroupObjects: map[uint32][]uint32{1: {2}},
		},
		{
			name:             "OptSignObject3",
			fi:               &twoGroupImage,
			opts:             []SignerOpt{OptSignObjects(3)},
			wantGroupObjects: map[uint32][]uint32{2: {3}},
		},
		{
			name:             "OptSignObjects",
			fi:               &twoGroupImage,
			opts:             []SignerOpt{OptSignObjects(1, 2, 3)},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}, 2: {3}},
		},
	}

	for _, tt := range tests {
		tt := tt
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
							got = append(got, od.GetID())
						}

						if !reflect.DeepEqual(got, want) {
							t.Errorf("got objects %v, want %v", got, want)
						}
					}
				}
			}
		})
	}
}

func TestSigner_Sign(t *testing.T) {
	e := getTestEntity(t)

	encrypted := getTestEntity(t)
	encrypted.PrivateKey.Encrypted = true

	tests := []struct {
		name      string
		inputFile string
		opts      []SignerOpt
		wantErr   bool
	}{
		{
			name:      "NoKeyMaterial",
			inputFile: "one-group.sif",
			wantErr:   true,
		},
		{
			name:      "EncryptedKey",
			inputFile: "one-group.sif",
			opts:      []SignerOpt{OptSignWithEntity(encrypted)},
			wantErr:   true,
		},
		{
			name:      "OneGroup",
			inputFile: "one-group.sif",
			opts:      []SignerOpt{OptSignWithEntity(e)},
		},
		{
			name:      "TwoGroups",
			inputFile: "two-groups.sif",
			opts:      []SignerOpt{OptSignWithEntity(e)},
		},
		{
			name:      "OptSignGroup1",
			inputFile: "two-groups.sif",
			opts:      []SignerOpt{OptSignWithEntity(e), OptSignGroup(1)},
		},
		{
			name:      "OptSignGroup2",
			inputFile: "two-groups.sif",
			opts:      []SignerOpt{OptSignWithEntity(e), OptSignGroup(2)},
		},
		{
			name:      "OptSignObject1",
			inputFile: "two-groups.sif",
			opts:      []SignerOpt{OptSignWithEntity(e), OptSignObjects(1)},
		},
		{
			name:      "OptSignObject2",
			inputFile: "two-groups.sif",
			opts:      []SignerOpt{OptSignWithEntity(e), OptSignObjects(2)},
		},
		{
			name:      "OptSignObject3",
			inputFile: "two-groups.sif",
			opts:      []SignerOpt{OptSignWithEntity(e), OptSignObjects(3)},
		},
		{
			name:      "OptSignObjects",
			inputFile: "two-groups.sif",
			opts:      []SignerOpt{OptSignWithEntity(e), OptSignObjects(1, 2, 3)},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Signing modifies the file, so work with a temporary file.
			tf, err := tempFileFrom(filepath.Join("testdata", "images", tt.inputFile))
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tf.Name())
			defer tf.Close()

			f, err := sif.LoadContainerFp(tf, false)
			if err != nil {
				t.Fatal(err)
			}
			defer f.UnloadContainer() // nolint:errcheck

			s, err := NewSigner(&f, tt.opts...)
			if err != nil {
				t.Fatal(err)
			}

			if err := s.Sign(); (err != nil) != tt.wantErr {
				t.Fatalf("got error %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
