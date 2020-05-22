// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"crypto"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sylabs/sif/pkg/sif"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
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
			wantErr: errInvalidObjectID,
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
			wantErr: errObjectNotFound,
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
					got = append(got, od.ID)
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
			wantErr: errInvalidGroupID,
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
					got = append(got, od.ID)
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

	d1, _, err := twoGroups.GetFromDescrID(1)
	if err != nil {
		t.Fatal(err)
	}

	d2, _, err := twoGroups.GetFromDescrID(2)
	if err != nil {
		t.Fatal(err)
	}

	d3, _, err := twoGroups.GetFromDescrID(3)
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
				ods:       []*sif.Descriptor{d1},
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
				ods:       []*sif.Descriptor{d1},
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
				ods:       []*sif.Descriptor{d1},
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
				ods:       []*sif.Descriptor{d2},
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
				ods:       []*sif.Descriptor{d1, d2},
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
				ods:       []*sif.Descriptor{d3},
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

				if err := verifyGolden(t.Name(), di.Fp); err != nil {
					t.Errorf("failed to verify golden: %v", err)
				}
			}
		})
	}
}
