package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	uuid "github.com/satori/go.uuid"
	"github.com/sylabs/sif/pkg/integrity"
	"github.com/sylabs/sif/pkg/sif"
	"golang.org/x/crypto/openpgp"
)

func createImage(path string, dis []sif.DescriptorInput) error {
	id, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("id generation failed: %v", err)
	}

	ci := sif.CreateInfo{
		Pathname:   path,
		Launchstr:  sif.HdrLaunch,
		Sifversion: sif.HdrVersion,
		ID:         id,
		InputDescr: dis,
	}

	_, err = sif.CreateContainer(ci)
	return err
}

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

	partSystemGroup1 := sif.DescriptorInput{
		Datatype: sif.DataPartition,
		Groupid:  sif.DescrGroupMask | 1,
		Size:     4,
		Data:     []byte{0xfa, 0xce, 0xfe, 0xed},
	}
	if err := partSystemGroup1.SetPartExtra(sif.FsRaw, sif.PartSystem, sif.HdrArch386); err != nil {
		return err
	}

	partPrimSysGroup1 := sif.DescriptorInput{
		Datatype: sif.DataPartition,
		Groupid:  sif.DescrGroupMask | 1,
		Size:     4,
		Data:     []byte{0xde, 0xad, 0xbe, 0xef},
	}
	if err := partPrimSysGroup1.SetPartExtra(sif.FsSquash, sif.PartPrimSys, sif.HdrArch386); err != nil {
		return err
	}

	partSystemGroup2 := sif.DescriptorInput{
		Datatype: sif.DataPartition,
		Groupid:  sif.DescrGroupMask | 2,
		Size:     4,
		Data:     []byte{0xba, 0xdd, 0xca, 0xfe},
	}
	if err := partSystemGroup2.SetPartExtra(sif.FsExt3, sif.PartSystem, sif.HdrArchAMD64); err != nil {
		return err
	}

	images := []struct {
		path     string
		dis      []sif.DescriptorInput
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
			dis: []sif.DescriptorInput{
				partSystemGroup1,
				partPrimSysGroup1,
			},
		},
		{
			path: "one-group-signed.sif",
			dis: []sif.DescriptorInput{
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
			dis: []sif.DescriptorInput{
				partSystemGroup1,
				partPrimSysGroup1,
				partSystemGroup2,
			},
		},
		{
			path: "two-groups-signed.sif",
			dis: []sif.DescriptorInput{
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
		path := filepath.Join("images", image.path)

		if err := createImage(path, image.dis); err != nil {
			return err
		}

		f, err := sif.LoadContainer(path, false)
		if err != nil {
			return err
		}
		defer f.UnloadContainer() // nolint:errcheck

		if image.sign {
			s, err := integrity.NewSigner(&f, image.signOpts...)
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
