package main

import (
	"log"
	"path/filepath"

	uuid "github.com/satori/go.uuid"
	"github.com/sylabs/sif/pkg/sif"
)

func createImage(path string, dis []sif.DescriptorInput) error {
	ci := sif.CreateInfo{
		Pathname:   path,
		Launchstr:  sif.HdrLaunch,
		Sifversion: sif.HdrVersion,
		ID:         uuid.NewV4(),
		InputDescr: dis,
	}

	_, err := sif.CreateContainer(ci)
	return err
}

func generateImages() error {
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
		path string
		dis  []sif.DescriptorInput
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

		// Images with three partitions in two groups.
		{
			path: "two-groups.sif",
			dis: []sif.DescriptorInput{
				partSystemGroup1,
				partPrimSysGroup1,
				partSystemGroup2,
			},
		},
	}

	for _, image := range images {
		path := filepath.Join("images", image.path)

		if err := createImage(path, image.dis); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	if err := generateImages(); err != nil {
		log.Fatal(err)
	}
}
