// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"fmt"
	"strings"
	"time"
)

// OutputHeader generates a string which displays each fields of the global Header
func (fimg *FileImage) OutputHeader() string {
	str := fmt.Sprintf("%s %s\n%s %s\n%s %s\n%s %s\n%s %s\n%s %s\n%s %s\n%s %d\n%s %d\n%s %d\n%s %d\n%s %d\n%s %d",
		"Launch:  ", string(fimg.header.Launch[:]),
		"Magic:   ", string(fimg.header.Magic[:]),
		"Version: ", string(fimg.header.Version[:]),
		"Arch:    ", string(fimg.header.Arch[:]),
		"ID:      ", fimg.header.ID,
		"Ctime:   ", time.Unix(fimg.header.Ctime, 0),
		"Mtime:   ", time.Unix(fimg.header.Mtime, 0),
		"Dfree:   ", fimg.header.Dfree,
		"Dtotal:  ", fimg.header.Dtotal,
		"Descoff: ", fimg.header.Descroff,
		"Descrlen:", fimg.header.Descrlen,
		"Dataoff: ", fimg.header.Dataoff,
		"Datalen: ", fimg.header.Datalen)
	return str
}

// OutputDescriptor generates a string which displays each fields of a descriptor
func (descr *Descriptor) OutputDescriptor() string {
	str := fmt.Sprintf("%s 0x%x\n%s %s\n%s %v\n%s 0x%x\n%s %d\n%s %d\n%s %d\n%s %s\n%s %s\n%s %d\n%s %d\n%s %s\n%s %v",
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
		"Private: ", descr.Private)
	return str
}

// GetHeader returns the loaded SIF global header
func (fimg *FileImage) GetHeader() *Header {
	return &fimg.header
}

// GetFromDescrID search for a descriptor with
func (fimg *FileImage) GetFromDescrID(ID string) (*Descriptor, int, error) {
	var match = -1

	for i, v := range fimg.descrArr {
		if v.Used == false {
			continue
		} else {
			if strings.HasPrefix(v.ID.String(), ID) {
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

	return &fimg.descrArr[match], match, nil
}
