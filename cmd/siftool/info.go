// Copyright (c) 2018, Divya Cote <divya.cote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/sylabs/sif/pkg/sif"
)

// readableSize returns the size in human readable format
func readableSize(size uint64) string {
	var divs int
	var conversion string

	for ; size != 0; size >>= 10 {
		if size < 1024 {
			break
		}
		divs++
	}

	switch divs {
	case 0:
		conversion = fmt.Sprintf("%d", size)
	case 1:
		conversion = fmt.Sprintf("%dKB", size)
	case 2:
		conversion = fmt.Sprintf("%dMB", size)
	case 3:
		conversion = fmt.Sprintf("%dGB", size)
	case 4:
		conversion = fmt.Sprintf("%dTB", size)
	}
	return conversion
}

// archStr returns a human readable version of SIF mach architecture
func archStr(arch string) string {
	archMap := map[string]string{
		sif.HdrArch386:      "386",
		sif.HdrArchAMD64:    "amd64",
		sif.HdrArchARM:      "arm",
		sif.HdrArchARM64:    "arm64",
		sif.HdrArchPPC64:    "ppc64",
		sif.HdrArchPPC64le:  "ppc64le",
		sif.HdrArchMIPS:     "mips",
		sif.HdrArchMIPSle:   "mipsle",
		sif.HdrArchMIPS64:   "mips64",
		sif.HdrArchMIPS64le: "mips64le",
		sif.HdrArchS390x:    "s390x",
	}
	if archMap[arch[:2]] == "" {
		return "unknown arch"
	}
	return archMap[arch[:2]]
}

// cmdHeader displays a SIF file global header to stdout
func cmdHeader(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage")
	}

	fimg, err := sif.LoadContainer(args[0], true)
	if err != nil {
		return fmt.Errorf("while loading SIF file: %s", err)
	}
	defer fimg.UnloadContainer()

	fmt.Println("Launch:  ", string(fimg.Header.Launch[:]))
	fmt.Println("Magic:   ", string(fimg.Header.Magic[:]))
	fmt.Println("Version: ", string(fimg.Header.Version[:]))
	fmt.Println("Arch:    ", archStr(string(fimg.Header.Arch[:])))
	fmt.Println("ID:      ", fimg.Header.ID)
	fmt.Println("Ctime:   ", time.Unix(fimg.Header.Ctime, 0))
	fmt.Println("Mtime:   ", time.Unix(fimg.Header.Mtime, 0))
	fmt.Println("Dfree:   ", fimg.Header.Dfree)
	fmt.Println("Dtotal:  ", fimg.Header.Dtotal)
	fmt.Println("Descoff: ", fimg.Header.Descroff)
	fmt.Println("Descrlen:", readableSize(uint64(fimg.Header.Descrlen)))
	fmt.Println("Dataoff: ", fimg.Header.Dataoff)
	fmt.Println("Datalen: ", readableSize(uint64(fimg.Header.Datalen)))

	return nil
}

// datatypeStr returns a string representation of a datatype
func datatypeStr(dtype sif.Datatype) string {
	switch dtype {
	case sif.DataDeffile:
		return "Def.FILE"
	case sif.DataEnvVar:
		return "Env.Vars"
	case sif.DataLabels:
		return "JSON.Labels"
	case sif.DataPartition:
		return "FS.Img"
	case sif.DataSignature:
		return "Signature"
	case sif.DataGenericJSON:
		return "JSON.Generic"
	}
	return "Unknown data-type"
}

// fstypeStr returns a string representation of a file system type
func fstypeStr(ftype sif.Fstype) string {
	switch ftype {
	case sif.FsSquash:
		return "Squashfs"
	case sif.FsExt3:
		return "Ext3"
	case sif.FsImmuObj:
		return "Data.Archive"
	case sif.FsRaw:
		return "Data.Raw"
	}
	return "Unknown fs-type"
}

// parttypeStr returns a string representation of a partition type
func parttypeStr(ptype sif.Parttype) string {
	switch ptype {
	case sif.PartSystem:
		return "System"
	case sif.PartData:
		return "Data"
	case sif.PartOverlay:
		return "Overlay"
	}
	return "Unknown part-type"
}

// hashtypeStr returns a string representation of a  hash type
func hashtypeStr(htype sif.Hashtype) string {
	switch htype {
	case sif.HashSHA256:
		return "SHA256"
	case sif.HashSHA384:
		return "SHA384"
	case sif.HashSHA512:
		return "SHA512"
	case sif.HashBLAKE2S:
		return "BLAKE2S"
	case sif.HashBLAKE2B:
		return "BLAKE2B"
	}
	return "Unknown hash-type"
}

// cmdList displays a list of all active descriptors from a SIF file to stdout
func cmdList(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage")
	}

	fimg, err := sif.LoadContainer(args[0], true)
	if err != nil {
		return fmt.Errorf("while loading SIF file: %s", err)
	}
	defer fimg.UnloadContainer()

	fmt.Println("Container id:", fimg.Header.ID)
	fmt.Println("Created on:  ", time.Unix(fimg.Header.Ctime, 0))
	fmt.Println("Modified on: ", time.Unix(fimg.Header.Mtime, 0))
	fmt.Println("----------------------------------------------------")

	fmt.Println("Descriptor list:")

	fmt.Printf("%-4s %-8s %-8s %-26s %s\n", "ID", "|GROUP", "|LINK", "|SIF POSITION (start-end)", "|TYPE")
	fmt.Println("------------------------------------------------------------------------------")

	for _, v := range fimg.DescrArr {
		if v.Used == false {
			continue
		} else {
			fmt.Printf("%-4d ", v.ID)
			if v.Groupid == sif.DescrUnusedGroup {
				fmt.Printf("|%-7s ", "NONE")
			} else {
				fmt.Printf("|%-7d ", v.Groupid&^sif.DescrGroupMask)
			}
			if v.Link == sif.DescrUnusedLink {
				fmt.Printf("|%-7s ", "NONE")
			} else {
				fmt.Printf("|%-7d ", v.Link)
			}

			fposbuf := fmt.Sprintf("|%d-%d ", v.Fileoff, v.Fileoff+v.Filelen-1)
			fmt.Printf("%-26s ", fposbuf)

			switch v.Datatype {
			case sif.DataPartition:
				f, _ := v.GetFsType()
				p, _ := v.GetPartType()
				fmt.Printf("|%s (%s/%s)", datatypeStr(v.Datatype), fstypeStr(f), parttypeStr(p))
			case sif.DataSignature:
				h, _ := v.GetHashType()
				fmt.Printf("|%s (%s)", datatypeStr(v.Datatype), hashtypeStr(h))
			default:
				fmt.Printf("|%s", datatypeStr(v.Datatype))
			}
			fmt.Println("")
		}
	}

	return nil
}

// cmdInfo displays detailed info about a descriptor from a SIF file to stdout
func cmdInfo(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("while converting input descriptor id: %s", err)
	}

	fimg, err := sif.LoadContainer(args[1], true)
	if err != nil {
		return fmt.Errorf("while loading SIF file: %s", err)
	}
	defer fimg.UnloadContainer()

	for i, v := range fimg.DescrArr {
		if v.Used == false {
			continue
		} else if v.ID == uint32(id) {
			fmt.Println("Descr slot#:", i)
			fmt.Println("  Datatype: ", datatypeStr(v.Datatype))
			fmt.Println("  ID:       ", v.ID)
			fmt.Println("  Used:     ", v.Used)
			if v.Groupid == sif.DescrUnusedGroup {
				fmt.Println("  Groupid:  ", "NONE")
			} else {
				fmt.Println("  Groupid:  ", v.Groupid&^sif.DescrGroupMask)
			}
			if v.Link == sif.DescrUnusedLink {
				fmt.Println("  Link:     ", "NONE")
			} else {
				fmt.Println("  Link:     ", v.Link)
			}
			fmt.Println("  Fileoff:  ", v.Fileoff)
			fmt.Println("  Filelen:  ", v.Filelen)
			fmt.Println("  Ctime:    ", time.Unix(v.Ctime, 0))
			fmt.Println("  Mtime:    ", time.Unix(v.Mtime, 0))
			fmt.Println("  UID:      ", v.UID)
			fmt.Println("  Gid:      ", v.Gid)
			fmt.Println("  Name:     ", string(v.Name[:]))
			switch v.Datatype {
			case sif.DataPartition:
				f, _ := v.GetFsType()
				p, _ := v.GetPartType()
				fmt.Println("  Fstype:   ", fstypeStr(f))
				fmt.Println("  Parttype: ", parttypeStr(p))
			case sif.DataSignature:
				h, _ := v.GetHashType()
				e, _ := v.GetEntityString()
				fmt.Println("  Hashtype: ", hashtypeStr(h))
				fmt.Println("  Entity:   ", e)
			}

			return nil
		}
	}

	return fmt.Errorf("descriptor not in range or currently unused")
}

// cmdDump extracts and output a data object from a SIF file to stdout
func cmdDump(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage")
	}

	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("while converting input descriptor id: %s", err)
	}

	fimg, err := sif.LoadContainer(args[1], true)
	if err != nil {
		return fmt.Errorf("while loading SIF file: %s", err)
	}
	defer fimg.UnloadContainer()

	for _, v := range fimg.DescrArr {
		if v.Used == false {
			continue
		} else if v.ID == uint32(id) {
			if _, err := fimg.Fp.Seek(v.Fileoff, 0); err != nil {
				return fmt.Errorf("while seeking to data object: %s", err)
			}
			if _, err := io.CopyN(os.Stdout, fimg.Fp, v.Filelen); err != nil {
				return fmt.Errorf("while copying data object to stdout: %s", err)
			}

			return nil
		}
	}

	return fmt.Errorf("descriptor not in range or currently unused")
}
