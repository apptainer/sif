// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/apptainer/sif/v2/pkg/integrity"
	"github.com/apptainer/sif/v2/pkg/sif"
)

func fixedTime() time.Time {
	return time.Date(2020, 6, 30, 0, 1, 56, 0, time.UTC)
}

var errUnexpectedNumEntities = errors.New("unexpected number of entities")

func getEntity() (*openpgp.Entity, error) {
	f, err := os.Open(filepath.Join("keys", "private.asc"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	el, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		return nil, err
	}

	if len(el) != 1 {
		return nil, errUnexpectedNumEntities
	}
	return el[0], nil
}

func generateImages() error {
	e, err := getEntity()
	if err != nil {
		return err
	}

	partSystemGroup1 := func() (sif.DescriptorInput, error) {
		return sif.NewDescriptorInput(sif.DataPartition,
			bytes.NewReader([]byte{0xfa, 0xce, 0xfe, 0xed}),
			sif.OptGroupID(1),
			sif.OptPartitionMetadata(sif.FsRaw, sif.PartSystem, "386"),
			sif.OptObjectName("."),
			sif.OptObjectTime(fixedTime()),
		)
	}

	partPrimSysGroup1 := func() (sif.DescriptorInput, error) {
		return sif.NewDescriptorInput(sif.DataPartition,
			bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef}),
			sif.OptGroupID(1),
			sif.OptPartitionMetadata(sif.FsSquash, sif.PartPrimSys, "386"),
			sif.OptObjectName("."),
			sif.OptObjectTime(fixedTime()),
		)
	}

	partSystemGroup2 := func() (sif.DescriptorInput, error) {
		return sif.NewDescriptorInput(sif.DataPartition,
			bytes.NewReader([]byte{0xba, 0xdd, 0xca, 0xfe}),
			sif.OptGroupID(2),
			sif.OptPartitionMetadata(sif.FsExt3, sif.PartSystem, "amd64"),
			sif.OptObjectName("."),
			sif.OptObjectTime(fixedTime()),
		)
	}

	images := []struct {
		path      string
		id        string
		createdAt time.Time
		diFns     []func() (sif.DescriptorInput, error)
		sign      bool
		signOpts  []integrity.SignerOpt
	}{
		// Images with no objects.
		{
			path:      "empty.sif",
			id:        "3fa802cc-358b-45e3-bcc0-69dc7a45f9f8",
			createdAt: time.Date(2020, 5, 22, 19, 30, 59, 0, time.UTC),
		},

		// Images with two partitions in one group.
		{
			path:      "one-group.sif",
			id:        "6ecc76b7-a497-4f7f-9ebd-8da2a04c6be1",
			createdAt: time.Date(2020, 5, 22, 19, 30, 59, 0, time.UTC),
			diFns: []func() (sif.DescriptorInput, error){
				partSystemGroup1,
				partPrimSysGroup1,
			},
		},
		{
			path:      "one-group-signed.sif",
			id:        "73e1c5c3-5c41-41ed-ad7c-2504d669f140",
			createdAt: time.Date(2020, 6, 30, 0, 1, 56, 0, time.UTC),
			diFns: []func() (sif.DescriptorInput, error){
				partSystemGroup1,
				partPrimSysGroup1,
			},
			sign: true,
			signOpts: []integrity.SignerOpt{
				integrity.OptSignWithEntity(e),
				integrity.OptSignWithTime(fixedTime),
			},
		},

		// Images with three partitions in two groups.
		{
			path:      "two-groups.sif",
			id:        "0b19ec2c-0b08-46c9-95ae-fa88cd9e48a1",
			createdAt: time.Date(2020, 5, 22, 19, 30, 59, 0, time.UTC),
			diFns: []func() (sif.DescriptorInput, error){
				partSystemGroup1,
				partPrimSysGroup1,
				partSystemGroup2,
			},
		},
		{
			path:      "two-groups-signed.sif",
			id:        "610cf3a3-18b0-4622-8b08-772d3510d7b5",
			createdAt: time.Date(2020, 6, 30, 0, 1, 56, 0, time.UTC),
			diFns: []func() (sif.DescriptorInput, error){
				partSystemGroup1,
				partPrimSysGroup1,
				partSystemGroup2,
			},
			sign: true,
			signOpts: []integrity.SignerOpt{
				integrity.OptSignWithEntity(e),
				integrity.OptSignWithTime(fixedTime),
			},
		},
	}

	for _, image := range images {
		dis := make([]sif.DescriptorInput, 0, len(image.diFns))
		for _, fn := range image.diFns {
			di, err := fn()
			if err != nil {
				return err
			}
			dis = append(dis, di)
		}

		path := filepath.Join("images", image.path)

		f, err := sif.CreateContainerAtPath(path,
			sif.OptCreateWithID(image.id),
			sif.OptCreateWithTime(image.createdAt),
			sif.OptCreateWithDescriptors(dis...),
			sif.OptCreateWithLaunchScript("#!/usr/bin/env run-singularity\n"),
		)
		if err != nil {
			return err
		}
		defer func() {
			if err := f.UnloadContainer(); err != nil {
				log.Printf("failed to unload container: %v", err)
			}
		}()

		if image.sign {
			s, err := integrity.NewSigner(f, image.signOpts...)
			if err != nil {
				return err
			}

			if err := s.Sign(); err != nil {
				return err
			}
		}
	}

	return nil
}

func main() {
	if err := generateImages(); err != nil {
		log.Fatal(err)
	}
}
