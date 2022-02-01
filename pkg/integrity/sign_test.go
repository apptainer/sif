// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/apptainer/sif/v2/pkg/sif"
	"github.com/sebdah/goldie/v2"
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
		tt := tt
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
				if want := tt.ids; !reflect.DeepEqual(got, want) {
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
			opts:        []groupSignerOpt{optSignGroupMetadataHash(crypto.SHA1)},
			wantObjects: []uint32{1, 2},
			wantMDHash:  crypto.SHA1,
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
					got = append(got, od.ID())
				}
				if want := tt.wantObjects; !reflect.DeepEqual(got, want) {
					t.Errorf("got objects %v, want %v", got, want)
				}

				if got, want := s.mdHash, tt.wantMDHash; got != want {
					t.Errorf("got metadata hash %v, want %v", got, want)
				}
			}
		})
	}
}

func TestGroupSigner_SignWithEntity(t *testing.T) {
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

	encrypted := getTestEntity(t)
	encrypted.PrivateKey.Encrypted = true

	tests := []struct {
		name    string
		gs      groupSigner
		e       *openpgp.Entity
		wantErr bool
	}{
		{
			name: "HashUnavailable",
			gs: groupSigner{
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d1},
				mdHash: crypto.MD4,
				sigConfig: &packet.Config{
					Time: fixedTime,
				},
			},
			e:       e,
			wantErr: true,
		},
		{
			name: "EncryptedKey",
			gs: groupSigner{
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d1},
				mdHash: crypto.SHA1,
				sigConfig: &packet.Config{
					Time: fixedTime,
				},
			},
			e:       encrypted,
			wantErr: true,
		},
		{
			name: "Object1",
			gs: groupSigner{
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d1},
				mdHash: crypto.SHA1,
				sigConfig: &packet.Config{
					Time: fixedTime,
				},
			},
			e: e,
		},
		{
			name: "Object2",
			gs: groupSigner{
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d2},
				mdHash: crypto.SHA1,
				sigConfig: &packet.Config{
					Time: fixedTime,
				},
			},
			e: e,
		},
		{
			name: "Group1",
			gs: groupSigner{
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d1, d2},
				mdHash: crypto.SHA1,
				sigConfig: &packet.Config{
					Time: fixedTime,
				},
			},
			e: e,
		},
		{
			name: "Group2",
			gs: groupSigner{
				f:      twoGroups,
				id:     2,
				ods:    []sif.Descriptor{d3},
				mdHash: crypto.SHA1,
				sigConfig: &packet.Config{
					Time: fixedTime,
				},
			},
			e: e,
		},
		{
			name: "SignatureConfigSHA256",
			gs: groupSigner{
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d1, d2},
				mdHash: crypto.SHA1,
				sigConfig: &packet.Config{
					DefaultHash: crypto.SHA256,
					Time:        fixedTime,
				},
			},
			e: e,
		},
		{
			name: "SignatureConfigSHA384",
			gs: groupSigner{
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d1, d2},
				mdHash: crypto.SHA1,
				sigConfig: &packet.Config{
					DefaultHash: crypto.SHA384,
					Time:        fixedTime,
				},
			},
			e: e,
		},
		{
			name: "SignatureConfigSHA512",
			gs: groupSigner{
				f:      twoGroups,
				id:     1,
				ods:    []sif.Descriptor{d1, d2},
				mdHash: crypto.SHA1,
				sigConfig: &packet.Config{
					DefaultHash: crypto.SHA512,
					Time:        fixedTime,
				},
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

				if err := fi.UnloadContainer(); err != nil {
					t.Error(err)
				}

				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, buf.Bytes())
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
			name:    "NilFileImage",
			fi:      nil,
			wantErr: errNilFileImage,
		},
		{
			name:    "NoGroupsFound",
			fi:      emptyImage,
			wantErr: errNoGroupsFound,
		},
		{
			name:    "InvalidGroupID",
			fi:      emptyImage,
			opts:    []SignerOpt{OptSignGroup(0)},
			wantErr: sif.ErrInvalidGroupID,
		},
		{
			name:    "NoObjectsSpecified",
			fi:      emptyImage,
			opts:    []SignerOpt{OptSignObjects()},
			wantErr: errNoObjectsSpecified,
		},
		{
			name:    "NoObjects",
			fi:      emptyImage,
			opts:    []SignerOpt{OptSignObjects(1)},
			wantErr: sif.ErrNoObjects,
		},
		{
			name:    "InvalidObjectID",
			fi:      oneGroupImage,
			opts:    []SignerOpt{OptSignObjects(0)},
			wantErr: sif.ErrInvalidObjectID,
		},
		{
			name:             "OneGroupDefaultObjects",
			fi:               oneGroupImage,
			opts:             []SignerOpt{},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}},
		},
		{
			name:             "TwoGroupDefaultObjects",
			fi:               twoGroupImage,
			opts:             []SignerOpt{},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}, 2: {3}},
		},
		{
			name:             "OptSignWithEntity",
			fi:               twoGroupImage,
			opts:             []SignerOpt{OptSignWithEntity(e)},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}, 2: {3}},
			wantEntity:       e,
		},
		{
			name:             "OptSignGroup1",
			fi:               twoGroupImage,
			opts:             []SignerOpt{OptSignGroup(1)},
			wantGroupObjects: map[uint32][]uint32{1: {1, 2}},
		},
		{
			name:             "OptSignGroup2",
			fi:               twoGroupImage,
			opts:             []SignerOpt{OptSignGroup(2)},
			wantGroupObjects: map[uint32][]uint32{2: {3}},
		},
		{
			name:             "OptSignObject1",
			fi:               twoGroupImage,
			opts:             []SignerOpt{OptSignObjects(1)},
			wantGroupObjects: map[uint32][]uint32{1: {1}},
		},
		{
			name:             "OptSignObject2",
			fi:               twoGroupImage,
			opts:             []SignerOpt{OptSignObjects(2)},
			wantGroupObjects: map[uint32][]uint32{1: {2}},
		},
		{
			name:             "OptSignObject3",
			fi:               twoGroupImage,
			opts:             []SignerOpt{OptSignObjects(3)},
			wantGroupObjects: map[uint32][]uint32{2: {3}},
		},
		{
			name:             "OptSignObjects",
			fi:               twoGroupImage,
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
							got = append(got, od.ID())
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
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
			},
		},
		{
			name:      "TwoGroups",
			inputFile: "two-groups.sif",
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
			},
		},
		{
			name:      "OptSignGroup1",
			inputFile: "two-groups.sif",
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignGroup(1),
			},
		},
		{
			name:      "OptSignGroup2",
			inputFile: "two-groups.sif",
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignGroup(2),
			},
		},
		{
			name:      "OptSignObject1",
			inputFile: "two-groups.sif",
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignObjects(1),
			},
		},
		{
			name:      "OptSignObject2",
			inputFile: "two-groups.sif",
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignObjects(2),
			},
		},
		{
			name:      "OptSignObject3",
			inputFile: "two-groups.sif",
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignObjects(3),
			},
		},
		{
			name:      "OptSignObjects",
			inputFile: "two-groups.sif",
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignObjects(1, 2, 3),
			},
		},
		{
			name:      "OptSignDeterministic",
			inputFile: "one-group.sif",
			opts: []SignerOpt{
				OptSignWithEntity(e),
				OptSignWithTime(fixedTime),
				OptSignDeterministic(),
			},
		},
	}

	for _, tt := range tests {
		tt := tt

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

			s, err := NewSigner(f, tt.opts...)
			if err != nil {
				t.Fatal(err)
			}

			if err := s.Sign(); (err != nil) != tt.wantErr {
				t.Fatalf("got error %v, wantErr %v", err, tt.wantErr)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, buf.Bytes())
		})
	}
}
