// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"errors"
)

// ErrNotFound is the code for when no search key is not found.
var ErrNotFound = errors.New("no match found")

// ErrMultValues is the code for when search key is not unique.
var ErrMultValues = errors.New("lookup would return more than one match")

// GetSIFArch returns the SIF arch code from go runtime arch code.
func GetSIFArch(goarch string) (sifarch string) {
	var ok bool

	archMap := map[string]string{
		"386":      HdrArch386,
		"amd64":    HdrArchAMD64,
		"arm":      HdrArchARM,
		"arm64":    HdrArchARM64,
		"ppc64":    HdrArchPPC64,
		"ppc64le":  HdrArchPPC64le,
		"mips":     HdrArchMIPS,
		"mipsle":   HdrArchMIPSle,
		"mips64":   HdrArchMIPS64,
		"mips64le": HdrArchMIPS64le,
		"s390x":    HdrArchS390x,
	}

	if sifarch, ok = archMap[goarch]; !ok {
		sifarch = HdrArchUnknown
	}
	return sifarch
}

// GetGoArch returns the go runtime arch code from the SIF arch code.
func GetGoArch(sifarch string) (goarch string) {
	var ok bool

	archMap := map[string]string{
		HdrArch386:      "386",
		HdrArchAMD64:    "amd64",
		HdrArchARM:      "arm",
		HdrArchARM64:    "arm64",
		HdrArchPPC64:    "ppc64",
		HdrArchPPC64le:  "ppc64le",
		HdrArchMIPS:     "mips",
		HdrArchMIPSle:   "mipsle",
		HdrArchMIPS64:   "mips64",
		HdrArchMIPS64le: "mips64le",
		HdrArchS390x:    "s390x",
	}

	if goarch, ok = archMap[sifarch]; !ok {
		goarch = "unknown"
	}
	return goarch
}

// GetFromDescrID searches for a descriptor with.
func (f *FileImage) GetFromDescrID(id uint32) (*Descriptor, int, error) {
	match := -1

	for i, v := range f.descrArr {
		if !v.Used {
			continue
		}
		if v.ID == id {
			if match != -1 {
				return nil, -1, ErrMultValues
			}
			match = i
		}
	}

	if match == -1 {
		return nil, -1, ErrNotFound
	}

	return &f.descrArr[match], match, nil
}

// GetLinkedDescrsByType searches for descriptors that point to "id", only returns the specified type.
func (f *FileImage) GetLinkedDescrsByType(id uint32, dataType Datatype) ([]*Descriptor, []int, error) {
	var descrs []*Descriptor
	var indexes []int

	for i, v := range f.descrArr {
		if !v.Used {
			continue
		}
		if v.Datatype == dataType && v.Link == id {
			indexes = append(indexes, i)
			descrs = append(descrs, &f.descrArr[i])
		}
	}

	if len(descrs) == 0 {
		return nil, nil, ErrNotFound
	}

	return descrs, indexes, nil
}

// GetFromLinkedDescr searches for descriptors that point to "id".
func (f *FileImage) GetFromLinkedDescr(id uint32) ([]*Descriptor, []int, error) {
	var descrs []*Descriptor
	var indexes []int
	var count int

	for i, v := range f.descrArr {
		if !v.Used {
			continue
		}
		if v.Link == id {
			indexes = append(indexes, i)
			descrs = append(descrs, &f.descrArr[i])
			count++
		}
	}

	if count == 0 {
		return nil, nil, ErrNotFound
	}

	return descrs, indexes, nil
}

// GetPartPrimSys returns the primary system partition if present. There should
// be only one primary system partition in a SIF file.
func (f *FileImage) GetPartPrimSys() (*Descriptor, int, error) {
	var descr *Descriptor
	index := -1

	for i, v := range f.descrArr {
		if !v.Used {
			continue
		}
		if v.Datatype == DataPartition {
			ptype, err := v.GetPartType()
			if err != nil {
				return nil, -1, err
			}
			if ptype == PartPrimSys {
				if index != -1 {
					return nil, -1, ErrMultValues
				}
				index = i
				descr = &f.descrArr[i]
			}
		}
	}

	if index == -1 {
		return nil, -1, ErrNotFound
	}

	return descr, index, nil
}
