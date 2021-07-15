// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// Package sif implements data structures and routines to create
// and access SIF files.
// 	- sif.go contains the data definition the file format.
//	- create.go implements the core functionality for the creation of
//	  of new SIF files.
//	- load.go implements the core functionality for the loading of
//	  existing SIF files.
//	- lookup.go mostly implements search/lookup and printing routines
//	  and access to specific descriptor/data found in SIF container files.
//
// Layout of a SIF file (example):
//
//     .================================================.
//     | GLOBAL HEADER: Sifheader                       |
//     | - launch: "#!/usr/bin/env..."                  |
//     | - magic: "SIF_MAGIC"                           |
//     | - version: "1"                                 |
//     | - arch: "4"                                    |
//     | - uuid: b2659d4e-bd50-4ea5-bd17-eec5e54f918e   |
//     | - ctime: 1504657553                            |
//     | - mtime: 1504657653                            |
//     | - ndescr: 3                                    |
//     | - descroff: 120                                | --.
//     | - descrlen: 432                                |   |
//     | - dataoff: 4096                                |   |
//     | - datalen: 619362                              |   |
//     |------------------------------------------------| <-'
//     | DESCR[0]: Sifdeffile                           |
//     | - Sifcommon                                    |
//     |   - datatype: DATA_DEFFILE                     |
//     |   - id: 1                                      |
//     |   - groupid: 1                                 |
//     |   - link: NONE                                 |
//     |   - fileoff: 4096                              | --.
//     |   - filelen: 222                               |   |
//     |------------------------------------------------| <-----.
//     | DESCR[1]: Sifpartition                         |   |   |
//     | - Sifcommon                                    |   |   |
//     |   - datatype: DATA_PARTITION                   |   |   |
//     |   - id: 2                                      |   |   |
//     |   - groupid: 1                                 |   |   |
//     |   - link: NONE                                 |   |   |
//     |   - fileoff: 4318                              | ----. |
//     |   - filelen: 618496                            |   | | |
//     | - fstype: Squashfs                             |   | | |
//     | - parttype: System                             |   | | |
//     | - content: Linux                               |   | | |
//     |------------------------------------------------|   | | |
//     | DESCR[2]: Sifsignature                         |   | | |
//     | - Sifcommon                                    |   | | |
//     |   - datatype: DATA_SIGNATURE                   |   | | |
//     |   - id: 3                                      |   | | |
//     |   - groupid: NONE                              |   | | |
//     |   - link: 2                                    | ------'
//     |   - fileoff: 622814                            | ------.
//     |   - filelen: 644                               |   | | |
//     | - hashtype: SHA384                             |   | | |
//     | - entity: @                                    |   | | |
//     |------------------------------------------------| <-' | |
//     | Definition file data                           |     | |
//     | .                                              |     | |
//     | .                                              |     | |
//     | .                                              |     | |
//     |------------------------------------------------| <---' |
//     | File system partition image                    |       |
//     | .                                              |       |
//     | .                                              |       |
//     | .                                              |       |
//     |------------------------------------------------| <-----'
//     | Signed verification data                       |
//     | .                                              |
//     | .                                              |
//     | .                                              |
//     `================================================'
//
package sif

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
)

// SIF header constants and quantities.
const (
	hdrLaunch     = "#!/usr/bin/env run-singularity\n"
	hdrLaunchLen  = 32 // len("#!/usr/bin/env... ")
	hdrMagic      = "SIF_MAGIC"
	hdrMagicLen   = 10 // len("SIF_MAGIC")
	hdrVersionLen = 3  // len("99")
	hdrArchLen    = 3  // len("99")
)

// SpecVersion specifies a SIF specification version.
type SpecVersion uint8

func (v SpecVersion) String() string { return fmt.Sprintf("%02d", v) }
func (v SpecVersion) bytes() []byte  { return []byte(v.String()) }

// SIF specification versions.
const (
	version01 SpecVersion = iota + 1
)

// CurrentVersion specifies the current SIF specification version.
const CurrentVersion = version01

// SIF architecture values.
const (
	HdrArchUnknown  = "00" // Undefined/Unsupported arch
	HdrArch386      = "01" // 386 (i[3-6]86) arch code
	HdrArchAMD64    = "02" // AMD64 arch code
	HdrArchARM      = "03" // ARM arch code
	HdrArchARM64    = "04" // AARCH64 arch code
	HdrArchPPC64    = "05" // PowerPC 64 arch code
	HdrArchPPC64le  = "06" // PowerPC 64 little-endian arch code
	HdrArchMIPS     = "07" // MIPS arch code
	HdrArchMIPSle   = "08" // MIPS little-endian arch code
	HdrArchMIPS64   = "09" // MIPS64 arch code
	HdrArchMIPS64le = "10" // MIPS64 little-endian arch code
	HdrArchS390x    = "11" // IBM s390x arch code
)

const (
	DescrNumEntries   = 48                 // the default total number of available descriptors
	DescrGroupMask    = 0xf0000000         // groups start at that offset
	DescrUnusedGroup  = DescrGroupMask     // descriptor without a group
	DescrDefaultGroup = DescrGroupMask | 1 // first groupid number created
	DescrUnusedLink   = 0                  // descriptor without link to other
	DescrEntityLen    = 256                // len("Joe Bloe <jbloe@gmail.com>...")
	DescrNameLen      = 128                // descriptor name (string identifier)
	DescrMaxPrivLen   = 384                // size reserved for descriptor specific data
	DescrStartOffset  = 4096               // where descriptors start after global header
	DataStartOffset   = 32768              // where data object start after descriptors
)

// Datatype represents the different SIF data object types stored in the image.
type Datatype int32

// List of supported SIF data types.
const (
	DataDeffile       Datatype = iota + 0x4001 // definition file data object
	DataEnvVar                                 // environment variables data object
	DataLabels                                 // JSON labels data object
	DataPartition                              // file system data object
	DataSignature                              // signing/verification data object
	DataGenericJSON                            // generic JSON meta-data
	DataGeneric                                // generic / raw data
	DataCryptoMessage                          // cryptographic message data object
)

// String returns a human-readable representation of t.
func (t Datatype) String() string {
	switch t {
	case DataDeffile:
		return "Def.FILE"
	case DataEnvVar:
		return "Env.Vars"
	case DataLabels:
		return "JSON.Labels"
	case DataPartition:
		return "FS"
	case DataSignature:
		return "Signature"
	case DataGenericJSON:
		return "JSON.Generic"
	case DataGeneric:
		return "Generic/Raw"
	case DataCryptoMessage:
		return "Cryptographic Message"
	}
	return "Unknown"
}

// Fstype represents the different SIF file system types found in partition data objects.
type Fstype int32

// List of supported file systems.
const (
	FsSquash            Fstype = iota + 1 // Squashfs file system, RDONLY
	FsExt3                                // EXT3 file system, RDWR (deprecated)
	FsImmuObj                             // immutable data object archive
	FsRaw                                 // raw data
	FsEncryptedSquashfs                   // Encrypted Squashfs file system, RDONLY
)

// String returns a human-readable representation of t.
func (t Fstype) String() string {
	switch t {
	case FsSquash:
		return "Squashfs"
	case FsExt3:
		return "Ext3"
	case FsImmuObj:
		return "Archive"
	case FsRaw:
		return "Raw"
	case FsEncryptedSquashfs:
		return "Encrypted squashfs"
	}
	return "Unknown"
}

// Parttype represents the different SIF container partition types (system and data).
type Parttype int32

// List of supported partition types.
const (
	PartSystem  Parttype = iota + 1 // partition hosts an operating system
	PartPrimSys                     // partition hosts the primary operating system
	PartData                        // partition hosts data only
	PartOverlay                     // partition hosts an overlay
)

// String returns a human-readable representation of t.
func (t Parttype) String() string {
	switch t {
	case PartSystem:
		return "System"
	case PartPrimSys:
		return "*System"
	case PartData:
		return "Data"
	case PartOverlay:
		return "Overlay"
	}
	return "Unknown"
}

// Hashtype represents the different SIF hashing function types used to fingerprint data objects.
type Hashtype int32

// List of supported hash functions.
const (
	HashSHA256 Hashtype = iota + 1
	HashSHA384
	HashSHA512
	HashBLAKE2S
	HashBLAKE2B
)

// String returns a human-readable representation of t.
func (t Hashtype) String() string {
	switch t {
	case HashSHA256:
		return "SHA256"
	case HashSHA384:
		return "SHA384"
	case HashSHA512:
		return "SHA512"
	case HashBLAKE2S:
		return "BLAKE2S"
	case HashBLAKE2B:
		return "BLAKE2B"
	}
	return "Unknown"
}

// Formattype represents the different formats used to store cryptographic message objects.
type Formattype int32

// List of supported cryptographic message formats.
const (
	FormatOpenPGP Formattype = iota + 1
	FormatPEM
)

// String returns a human-readable representation of t.
func (t Formattype) String() string {
	switch t {
	case FormatOpenPGP:
		return "OpenPGP"
	case FormatPEM:
		return "PEM"
	}
	return "Unknown"
}

// Messagetype represents the different messages stored within cryptographic message objects.
type Messagetype int32

// List of supported cryptographic message formats.
const (
	// openPGP formatted messages.
	MessageClearSignature Messagetype = 0x100

	// PEM formatted messages.
	MessageRSAOAEP Messagetype = 0x200
)

// String returns a human-readable representation of t.
func (t Messagetype) String() string {
	switch t {
	case MessageClearSignature:
		return "Clear Signature"
	case MessageRSAOAEP:
		return "RSA-OAEP"
	}
	return "Unknown"
}

// SIF data object deletion strategies.
const (
	DelZero    = iota + 1 // zero the data object bytes
	DelCompact            // free the space used by data object
)

// Deffile represents the SIF definition-file data object descriptor.
type Deffile struct{}

// Labels represents the SIF JSON-labels data object descriptor.
type Labels struct{}

// Envvar represents the SIF envvar data object descriptor.
type Envvar struct{}

// Partition represents the SIF partition data object descriptor.
type Partition struct {
	Fstype   Fstype
	Parttype Parttype
	Arch     [hdrArchLen]byte // arch the image is built for
}

// Signature represents the SIF signature data object descriptor.
type Signature struct {
	Hashtype Hashtype
	Entity   [DescrEntityLen]byte
}

// GenericJSON represents the SIF generic JSON meta-data data object descriptor.
type GenericJSON struct{}

// Generic represents the SIF generic data object descriptor.
type Generic struct{}

// CryptoMessage represents the SIF crypto message object descriptor.
type CryptoMessage struct {
	Formattype  Formattype
	Messagetype Messagetype
}

// header describes a loaded SIF file.
type header struct {
	Launch [hdrLaunchLen]byte // #! shell execution line

	Magic   [hdrMagicLen]byte   // look for "SIF_MAGIC"
	Version [hdrVersionLen]byte // SIF version
	Arch    [hdrArchLen]byte    // arch the primary partition is built for
	ID      uuid.UUID           // image unique identifier

	Ctime int64 // image creation time
	Mtime int64 // last modification time

	Dfree    int64 // # of unused data object descr.
	Dtotal   int64 // # of total available data object descr.
	Descroff int64 // bytes into file where descs start
	Descrlen int64 // bytes used by all current descriptors
	Dataoff  int64 // bytes into file where data starts
	Datalen  int64 // bytes used by all data objects
}

// GetIntegrityReader returns an io.Reader that reads the integrity-protected fields from h.
func (h header) GetIntegrityReader() io.Reader {
	return io.MultiReader(
		bytes.NewReader(h.Launch[:]),
		bytes.NewReader(h.Magic[:]),
		bytes.NewReader(h.Version[:]),
		bytes.NewReader(h.ID[:]),
	)
}

//
// This section describes SIF creation/loading data structures used when
// building or opening a SIF file. Transient data not found in the final
// SIF file. Those data structures are internal.
//

// ReadWriter describes the operations needed to support reading and
// writing SIF files.
type ReadWriter interface {
	io.ReadWriteSeeker
	io.ReaderAt
	io.Closer
	Name() string
	Fd() uintptr
	Stat() (os.FileInfo, error)
	Sync() error
	Truncate(size int64) error
}

// FileImage describes the representation of a SIF file in memory.
type FileImage struct {
	h          header        // the loaded SIF global header
	fp         ReadWriter    // file pointer of opened SIF file
	size       int64         // file size of the opened SIF file
	Filedata   []byte        // Deprecated: Filedata exists for historical compatibility and should not be used.
	Amodebuf   bool          // Deprecated: Amodebuf exists for historical compatibility and should not be used.
	Reader     *bytes.Reader // Deprecated: Reader exists for historical compatibility and should not be used.
	descrArr   []Descriptor  // slice of loaded descriptors from SIF file
	PrimPartID uint32        // ID of primary system partition if present
}

// LaunchScript returns the image launch script.
func (f *FileImage) LaunchScript() string { return trimZeroBytes(f.h.Launch[:]) }

// Version returns the SIF specification version of the image.
func (f *FileImage) Version() string { return trimZeroBytes(f.h.Version[:]) }

// PrimaryArch returns the primary CPU architecture of the image.
func (f *FileImage) PrimaryArch() string { return GetGoArch(trimZeroBytes(f.h.Arch[:])) }

// ID returns the ID of the image.
func (f *FileImage) ID() string { return f.h.ID.String() }

// CreatedAt returns the creation time of the image.
func (f *FileImage) CreatedAt() time.Time { return time.Unix(f.h.Ctime, 0).UTC() }

// ModifiedAt returns the last modification time of the image.
func (f *FileImage) ModifiedAt() time.Time { return time.Unix(f.h.Mtime, 0).UTC() }

// DescriptorsFree returns the number of free descriptors in the image.
func (f *FileImage) DescriptorsFree() uint64 { return uint64(f.h.Dfree) }

// DescriptorsTotal returns the total number of descriptors in the image.
func (f *FileImage) DescriptorsTotal() uint64 { return uint64(f.h.Dtotal) }

// DescriptorSectionOffset returns the offset (in bytes) of the descriptors section in the image.
func (f *FileImage) DescriptorSectionOffset() uint64 { return uint64(f.h.Descroff) }

// DescriptorSectionSize returns the size (in bytes) of the descriptors section in the image.
func (f *FileImage) DescriptorSectionSize() uint64 { return uint64(f.h.Descrlen) }

// DataSectionOffset returns the offset (in bytes) of the data section in the image.
func (f *FileImage) DataSectionOffset() uint64 { return uint64(f.h.Dataoff) }

// DataSectionSize returns the size (in bytes) of the data section in the image.
func (f *FileImage) DataSectionSize() uint64 { return uint64(f.h.Datalen) }

// GetHeaderIntegrityReader returns an io.Reader that reads the integrity-protected fields from the
// header of the image.
func (f *FileImage) GetHeaderIntegrityReader() io.Reader {
	return f.h.GetIntegrityReader()
}

// WithDescriptors calls fn with each in-use descriptor in f.
func (f *FileImage) WithDescriptors(fn func(d *Descriptor) error) error {
	for i, d := range f.descrArr {
		if !d.Used {
			continue
		}

		if err := fn(&f.descrArr[i]); err != nil {
			return err
		}
	}

	return nil
}

// DescriptorInput describes the common info needed to create a data object descriptor.
type DescriptorInput struct {
	Datatype  Datatype // datatype being harvested for new descriptor
	Groupid   uint32   // group to be set for new descriptor
	Link      uint32   // link to be set for new descriptor
	Size      int64    // size of the data object for the new descriptor
	Alignment int      // Align requirement for data object

	Fname string    // file containing data associated with the new descriptor
	Fp    io.Reader // file pointer to opened 'fname'
	Data  []byte    // loaded data from file

	Image *FileImage  // loaded SIF file in memory
	Descr *Descriptor // created end result descriptor

	Extra bytes.Buffer // where specific input type store their data
}
