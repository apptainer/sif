// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/hpcng/sif/v2/pkg/integrity"
	"github.com/hpcng/sif/v2/pkg/sif"
	"golang.org/x/crypto/openpgp"
)

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

	if got, want := len(el), 1; got != want {
		return nil, fmt.Errorf("got %v entities, want %v", got, want)
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
		)
	}

	partPrimSysGroup1 := func() (sif.DescriptorInput, error) {
		return sif.NewDescriptorInput(sif.DataPartition,
			bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef}),
			sif.OptGroupID(1),
			sif.OptPartitionMetadata(sif.FsSquash, sif.PartPrimSys, "386"),
		)
	}

	partSystemGroup2 := func() (sif.DescriptorInput, error) {
		return sif.NewDescriptorInput(sif.DataPartition,
			bytes.NewReader([]byte{0xba, 0xdd, 0xca, 0xfe}),
			sif.OptGroupID(2),
			sif.OptPartitionMetadata(sif.FsSquash, sif.PartSystem, "amd64"),
		)
	}

	images := []struct {
		path     string
		diFns    []func() (sif.DescriptorInput, error)
		sign     bool
		signOpts []integrity.SignerOpt
	}{
		// Images with no objects.
		{
			path: "empty.sif",
		},

		// Images with two partitions in one group.
		{
			path: "one-group.sif",
			diFns: []func() (sif.DescriptorInput, error){
				partSystemGroup1,
				partPrimSysGroup1,
			},
		},
		{
			path: "one-group-signed.sif",
			diFns: []func() (sif.DescriptorInput, error){
				partSystemGroup1,
				partPrimSysGroup1,
			},
			sign: true,
			signOpts: []integrity.SignerOpt{
				integrity.OptSignWithEntity(e),
			},
		},

		// Images with three partitions in two groups.
		{
			path: "two-groups.sif",
			diFns: []func() (sif.DescriptorInput, error){
				partSystemGroup1,
				partPrimSysGroup1,
				partSystemGroup2,
			},
		},
		{
			path: "two-groups-signed.sif",
			diFns: []func() (sif.DescriptorInput, error){
				partSystemGroup1,
				partPrimSysGroup1,
				partSystemGroup2,
			},
			sign: true,
			signOpts: []integrity.SignerOpt{
				integrity.OptSignWithEntity(e),
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

		f, err := sif.CreateContainerAtPath(path, sif.OptCreateWithDescriptors(dis...))
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
