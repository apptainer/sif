// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

//
// Methods on (fimg *FIleImage)
//

// OutputHeader generates a string which displays each fields of the global Header
func (fimg *FileImage) OutputHeader() string {
	str := fmt.Sprintf("%s %s\n%s %s\n%s %s\n%s %s\n%s %v\n%s %s\n%s %s\n%s %d\n%s %d\n%s %d\n%s %d\n%s %d\n%s %d",
		"Launch:  ", string(fimg.Header.Launch[:]),
		"Magic:   ", string(fimg.Header.Magic[:]),
		"Version: ", string(fimg.Header.Version[:]),
		"Arch:    ", string(fimg.Header.Arch[:]),
		"ID:      ", fimg.Header.ID,
		"Ctime:   ", time.Unix(fimg.Header.Ctime, 0),
		"Mtime:   ", time.Unix(fimg.Header.Mtime, 0),
		"Dfree:   ", fimg.Header.Dfree,
		"Dtotal:  ", fimg.Header.Dtotal,
		"Descoff: ", fimg.Header.Descroff,
		"Descrlen:", fimg.Header.Descrlen,
		"Dataoff: ", fimg.Header.Dataoff,
		"Datalen: ", fimg.Header.Datalen)
	return str
}

// GetHeader returns the loaded SIF global header
func (fimg *FileImage) GetHeader() *Header {
	return &fimg.Header
}

// GetFromDescrID searches for a descriptor with
func (fimg *FileImage) GetFromDescrID(id uint32) (*Descriptor, int, error) {
	var match = -1

	for i, v := range fimg.DescrArr {
		if v.Used == false {
			continue
		} else {
			if v.ID == id {
				if match != -1 {
					return nil, -1, fmt.Errorf("key collision, be more precise")
				}
				match = i
			}
		}
	}

	if match == -1 {
		return nil, -1, fmt.Errorf("key not found")
	}

	return &fimg.DescrArr[match], match, nil
}

// GetPartFromGroup searches for a partition descriptor inside a specific group
func (fimg *FileImage) GetPartFromGroup(groupid uint32) (*Descriptor, int, error) {
	var match = -1

	for i, v := range fimg.DescrArr {
		if v.Used == false {
			continue
		} else {
			if v.Datatype == DataPartition && v.Groupid == groupid {
				if match != -1 {
					return nil, -1, fmt.Errorf("key collision, be more precise")
				}
				match = i
			}
		}
	}

	if match == -1 {
		return nil, -1, fmt.Errorf("key not found")
	}

	return &fimg.DescrArr[match], match, nil
}

// GetSignFromGroup searches for a signature descriptor inside a specific group
func (fimg *FileImage) GetSignFromGroup(groupid uint32) (*Descriptor, int, error) {
	var match = -1

	for i, v := range fimg.DescrArr {
		if v.Used == false {
			continue
		} else {
			if v.Datatype == DataSignature && v.Groupid == groupid {
				if match != -1 {
					return nil, -1, fmt.Errorf("key collision, be more precise")
				}
				match = i
			}
		}
	}

	if match == -1 {
		return nil, -1, fmt.Errorf("key not found")
	}

	return &fimg.DescrArr[match], match, nil
}

// GetFromLinkedDescr searches for a descriptor that points to "id"
func (fimg *FileImage) GetFromLinkedDescr(ID uint32) (*Descriptor, int, error) {
	var match = -1

	for i, v := range fimg.DescrArr {
		if v.Used == false {
			continue
		} else {
			if v.Link == ID {
				if match != -1 {
					return nil, -1, fmt.Errorf("key collision, be more precise")
				}
				match = i
			}
		}
	}

	if match == -1 {
		return nil, -1, fmt.Errorf("key not found")
	}

	return &fimg.DescrArr[match], match, nil
}

//
// Methods on (descr *Descriptor)
//

// OutputDescriptor generates a string which displays each fields of a descriptor
func (descr *Descriptor) OutputDescriptor() string {
	str := fmt.Sprintf("%s 0x%x\n%s %v\n%s %v\n%s 0x%x\n%s %d\n%s %d\n%s %d\n%s %s\n%s %s\n%s %d\n%s %d\n%s %s\n%s %v",
		"Datatype:", descr.Datatype,
		"ID:      ", descr.ID,
		"Used:    ", descr.Used,
		"Groupid: ", descr.Groupid,
		"Link:    ", descr.Link,
		"Fileoff: ", descr.Fileoff,
		"Filelen: ", descr.Filelen,
		"Ctime:   ", time.Unix(descr.Ctime, 0),
		"Mtime:   ", time.Unix(descr.Mtime, 0),
		"UID:     ", descr.UID,
		"Gid:     ", descr.Gid,
		"Name:    ", string(descr.Name[:]),
		"Extra: ", descr.Extra)
	return str
}

// GetName returns the name tag associated with the descriptor. Analogous to file name.
func (descr *Descriptor) GetName() string {
	return strings.TrimRight(string(descr.Name[:]), "\000")
}

// GetFsType extracts the Fstype field from the Extra field of a Partition Descriptor
func (descr *Descriptor) GetFsType() (Fstype, error) {
	if descr.Datatype != DataPartition {
		return -1, fmt.Errorf("expected DataPartition, got %v", descr.Datatype)
	}

	var pinfo Partition
	b := bytes.NewReader(descr.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &pinfo); err != nil {
		return -1, fmt.Errorf("while extracting Partition extra info: %s", err)
	}

	return pinfo.Fstype, nil
}

// GetPartType extracts the Parttype field from the Extra field of a Partition Descriptor
func (descr *Descriptor) GetPartType() (Parttype, error) {
	if descr.Datatype != DataPartition {
		return -1, fmt.Errorf("expected DataPartition, got %v", descr.Datatype)
	}

	var pinfo Partition
	b := bytes.NewReader(descr.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &pinfo); err != nil {
		return -1, fmt.Errorf("while extracting Partition extra info: %s", err)
	}

	return pinfo.Parttype, nil
}

// GetHashType extracts the Hashtype field from the Extra field of a Signature Descriptor
func (descr *Descriptor) GetHashType() (Hashtype, error) {
	if descr.Datatype != DataSignature {
		return -1, fmt.Errorf("expected DataSignature, got %v", descr.Datatype)
	}

	var sinfo Signature
	b := bytes.NewReader(descr.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &sinfo); err != nil {
		return -1, fmt.Errorf("while extracting Signature extra info: %s", err)
	}

	return sinfo.Hashtype, nil
}

// GetEntity extracts the signing entity field from the Extra field of a Signature Descriptor
func (descr *Descriptor) GetEntity() ([]byte, error) {
	if descr.Datatype != DataSignature {
		return nil, fmt.Errorf("expected DataSignature, got %v", descr.Datatype)
	}

	var sinfo Signature
	b := bytes.NewReader(descr.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &sinfo); err != nil {
		return nil, fmt.Errorf("while extracting Signature extra info: %s", err)
	}

	return sinfo.Entity[:], nil
}
