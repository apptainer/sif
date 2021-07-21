// Copyright (c) 2019-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2018, Divya Cote <divya.cote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"fmt"
	"time"
)

// FmtDescrList formats the output of a list of all active descriptors from a SIF file.
//
// Deprecated: FmtDescrList will be removed in a future release.
func (f *FileImage) FmtDescrList() string {
	s := fmt.Sprintf("%-4s %-8s %-8s %-26s %s\n", "ID", "|GROUP", "|LINK", "|SIF POSITION (start-end)", "|TYPE")
	s += fmt.Sprintln("------------------------------------------------------------------------------")

	for _, v := range f.descrArr {
		if !v.Used {
			continue
		} else {
			s += fmt.Sprintf("%-4d ", v.ID)
			if v.Groupid == DescrUnusedGroup {
				s += fmt.Sprintf("|%-7s ", "NONE")
			} else {
				s += fmt.Sprintf("|%-7d ", v.Groupid&^DescrGroupMask)
			}
			if v.Link == DescrUnusedLink {
				s += fmt.Sprintf("|%-7s ", "NONE")
			} else {
				if v.Link&DescrGroupMask == DescrGroupMask {
					s += fmt.Sprintf("|%-3d (G) ", v.Link&^DescrGroupMask)
				} else {
					s += fmt.Sprintf("|%-7d ", v.Link)
				}
			}

			fposbuf := fmt.Sprintf("|%d-%d ", v.Fileoff, v.Fileoff+v.Filelen)
			s += fmt.Sprintf("%-26s ", fposbuf)

			switch v.Datatype {
			case DataPartition:
				f, p, a, _ := v.GetPartitionMetadata()
				s += fmt.Sprintf("|%s (%s/%s/%s)\n", v.Datatype, f, p, a)
			case DataSignature:
				h, _ := v.GetHashType()
				s += fmt.Sprintf("|%s (%s)\n", v.Datatype, h)
			case DataCryptoMessage:
				f, _ := v.GetFormatType()
				m, _ := v.GetMessageType()
				s += fmt.Sprintf("|%s (%s/%s)\n", v.Datatype, f, m)
			default:
				s += fmt.Sprintf("|%s\n", v.Datatype)
			}
		}
	}

	return s
}

// FmtDescrInfo formats the output of detailed info about a descriptor from a SIF file.
//
// Deprecated: FmtDescrInfo will be removed in a future release.
func (f *FileImage) FmtDescrInfo(id uint32) string {
	var s string

	for i, v := range f.descrArr {
		if !v.Used {
			continue
		} else if v.ID == id {
			s = fmt.Sprintln("Descr slot#:", i)
			s += fmt.Sprintln("  Datatype: ", v.Datatype)
			s += fmt.Sprintln("  ID:       ", v.ID)
			s += fmt.Sprintln("  Used:     ", v.Used)
			if v.Groupid == DescrUnusedGroup {
				s += fmt.Sprintln("  Groupid:  ", "NONE")
			} else {
				s += fmt.Sprintln("  Groupid:  ", v.Groupid&^DescrGroupMask)
			}
			if v.Link == DescrUnusedLink {
				s += fmt.Sprintln("  Link:     ", "NONE")
			} else {
				if v.Link&DescrGroupMask == DescrGroupMask {
					s += fmt.Sprintln("  Link:     ", v.Link&^DescrGroupMask, "(G)")
				} else {
					s += fmt.Sprintln("  Link:     ", v.Link)
				}
			}
			s += fmt.Sprintln("  Fileoff:  ", v.Fileoff)
			s += fmt.Sprintln("  Filelen:  ", v.Filelen)
			s += fmt.Sprintln("  Ctime:    ", time.Unix(v.Ctime, 0).UTC())
			s += fmt.Sprintln("  Mtime:    ", time.Unix(v.Mtime, 0).UTC())
			s += fmt.Sprintln("  Name:     ", trimZeroBytes(v.Name[:]))
			switch v.Datatype {
			case DataPartition:
				f, p, a, _ := v.GetPartitionMetadata()
				s += fmt.Sprintln("  Fstype:   ", f)
				s += fmt.Sprintln("  Parttype: ", p)
				s += fmt.Sprintln("  Arch:     ", a)
			case DataSignature:
				h, _ := v.GetHashType()
				e, _ := v.GetEntityString()
				s += fmt.Sprintln("  Hashtype: ", h)
				s += fmt.Sprintln("  Entity:   ", e)
			case DataCryptoMessage:
				f, _ := v.GetFormatType()
				m, _ := v.GetMessageType()
				s += fmt.Sprintln("  Fmttype:  ", f)
				s += fmt.Sprintln("  Msgtype:  ", m)
			}

			return s
		}
	}

	return ""
}
