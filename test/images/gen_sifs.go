// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package main

import (
	"bytes"
	"crypto"
	"errors"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/apptainer/sif/v2/pkg/integrity"
	"github.com/apptainer/sif/v2/pkg/sif"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// getSigner returns a Signer read from the PEM file at path.
func getSigner(name string) (signature.Signer, error) { //nolint:ireturn
	path := filepath.Join("..", "keys", name)
	return signature.LoadSignerFromPEMFile(path, crypto.SHA256, cryptoutils.SkipPassword)
}

var errUnexpectedNumEntities = errors.New("unexpected number of entities")

func getEntity() (*openpgp.Entity, error) {
	f, err := os.Open(filepath.Join("..", "keys", "private.asc"))
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
	ed25519, err := getSigner("ed25519-private.pem")
	if err != nil {
		return err
	}

	rsa, err := getSigner("rsa-private.pem")
	if err != nil {
		return err
	}

	e, err := getEntity()
	if err != nil {
		return err
	}

	objectGenericJSON := func() (sif.DescriptorInput, error) {
		return sif.NewDescriptorInput(sif.DataGenericJSON,
			bytes.NewReader([]byte{0x7b, 0x7d}),
			sif.OptObjectName("data.json"),
		)
	}

	objectCryptoMessage := func() (sif.DescriptorInput, error) {
		return sif.NewDescriptorInput(sif.DataCryptoMessage,
			bytes.NewReader([]byte{0xfe, 0xfe, 0xf0, 0xf0}),
			sif.OptCryptoMessageMetadata(sif.FormatOpenPGP, sif.MessageClearSignature),
		)
	}

	objectSBOM := func() (sif.DescriptorInput, error) {
		b, err := os.ReadFile(filepath.Join("..", "input", "sbom.cdx.json"))
		if err != nil {
			return sif.DescriptorInput{}, err
		}

		return sif.NewDescriptorInput(sif.DataSBOM, bytes.NewReader(b),
			sif.OptSBOMMetadata(sif.SBOMFormatCycloneDXJSON),
		)
	}

	partSystem := func() (sif.DescriptorInput, error) {
		return sif.NewDescriptorInput(sif.DataPartition,
			bytes.NewReader([]byte{0xfa, 0xce, 0xfe, 0xed}),
			sif.OptPartitionMetadata(sif.FsRaw, sif.PartSystem, "386"),
		)
	}

	partPrimSys := func() (sif.DescriptorInput, error) {
		b, err := os.ReadFile(filepath.Join("..", "input", "root.squashfs"))
		if err != nil {
			return sif.DescriptorInput{}, err
		}

		return sif.NewDescriptorInput(sif.DataPartition, bytes.NewReader(b),
			sif.OptPartitionMetadata(sif.FsSquash, sif.PartPrimSys, "386"),
		)
	}

	partSystemGroup2 := func() (sif.DescriptorInput, error) {
		b, err := os.ReadFile(filepath.Join("..", "input", "root.ext3"))
		if err != nil {
			return sif.DescriptorInput{}, err
		}

		return sif.NewDescriptorInput(sif.DataPartition, bytes.NewReader(b),
			sif.OptPartitionMetadata(sif.FsExt3, sif.PartSystem, "amd64"),
			sif.OptGroupID(2),
		)
	}

	images := []struct {
		path     string
		diFns    []func() (sif.DescriptorInput, error)
		opts     []sif.CreateOpt
		signOpts []integrity.SignerOpt
	}{
		// Images with no objects.
		{
			path: "empty.sif",
		},
		{
			path: "empty-id.sif",
			opts: []sif.CreateOpt{
				sif.OptCreateWithID("3fa802cc-358b-45e3-bcc0-69dc7a45f9f8"),
			},
		},
		{
			path: "empty-launch-script.sif",
			opts: []sif.CreateOpt{
				sif.OptCreateWithLaunchScript("#!/usr/bin/env run-script\n"),
			},
		},

		// Images with one data object in one group.
		{
			path: "one-object-time.sif",
			opts: []sif.CreateOpt{
				sif.OptCreateWithTime(time.Date(2020, 6, 30, 0, 1, 56, 0, time.UTC)),
			},
			diFns: []func() (sif.DescriptorInput, error){
				objectGenericJSON,
			},
		},
		{
			path: "one-object-generic-json.sif",
			diFns: []func() (sif.DescriptorInput, error){
				objectGenericJSON,
			},
		},
		{
			path: "one-object-crypt-message.sif",
			diFns: []func() (sif.DescriptorInput, error){
				objectCryptoMessage,
			},
		},
		{
			path: "one-object-sbom.sif",
			diFns: []func() (sif.DescriptorInput, error){
				objectSBOM,
			},
		},

		// Images with two partitions in one group.
		{
			path: "one-group.sif",
			diFns: []func() (sif.DescriptorInput, error){
				partSystem,
				partPrimSys,
			},
		},
		{
			path: "one-group-signed-dsse.sif",
			diFns: []func() (sif.DescriptorInput, error){
				partSystem,
				partPrimSys,
			},
			signOpts: []integrity.SignerOpt{
				integrity.OptSignWithSigner(ed25519, rsa),
			},
		},
		{
			path: "one-group-signed-pgp.sif",
			diFns: []func() (sif.DescriptorInput, error){
				partSystem,
				partPrimSys,
			},
			signOpts: []integrity.SignerOpt{
				integrity.OptSignWithEntity(e),
			},
		},

		// Images with three partitions in two groups.
		{
			path: "two-groups.sif",
			diFns: []func() (sif.DescriptorInput, error){
				partSystem,
				partPrimSys,
				partSystemGroup2,
			},
		},
		{
			path: "two-groups-signed-dsse.sif",
			diFns: []func() (sif.DescriptorInput, error){
				partSystem,
				partPrimSys,
				partSystemGroup2,
			},
			signOpts: []integrity.SignerOpt{
				integrity.OptSignWithSigner(ed25519, rsa),
			},
		},
		{
			path: "two-groups-signed-pgp.sif",
			diFns: []func() (sif.DescriptorInput, error){
				partSystem,
				partPrimSys,
				partSystemGroup2,
			},
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

		opts := []sif.CreateOpt{
			sif.OptCreateDeterministic(),
			sif.OptCreateWithDescriptors(dis...),
		}
		opts = append(opts, image.opts...)

		f, err := sif.CreateContainerAtPath(image.path, opts...)
		if err != nil {
			return err
		}
		defer func() {
			if err := f.UnloadContainer(); err != nil {
				log.Printf("failed to unload container: %v", err)
			}
		}()

		if opts := image.signOpts; opts != nil {
			opts = append(opts,
				integrity.OptSignWithTime(func() time.Time { return time.Date(2020, 6, 30, 0, 1, 56, 0, time.UTC) }),
				integrity.OptSignDeterministic(),
			)

			s, err := integrity.NewSigner(f, opts...)
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
