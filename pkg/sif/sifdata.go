// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// Package sif implements data structures and routines to create
// and access SIF files. sifdata.go contains the data definition
// the file format. sif.go implements the core functionality of the
// file image format. sifaccess.go implements mostly search routines
// and access to specific descriptor/data found in SIF container files.
package sif

import (
	"bytes"
	"container/list"
	"github.com/satori/go.uuid"
	"os"
)

// Layout of a SIF file (example)
//
// .================================================.
// | GLOBAL HEADER: Sifheader                       |
// | - launch: "#!/usr/bin/env..."                  |
// | - magic: "SIF_MAGIC"                           |
// | - version: "1"                                 |
// | - arch: "4"                                    |
// | - uuid: b2659d4e-bd50-4ea5-bd17-eec5e54f918e   |
// | - ctime: 1504657553                            |
// | - mtime: 1504657653                            |
// | - ndescr: 3                                    |
// | - descroff: 120                                | --.
// | - descrlen: 432                                |   |
// | - dataoff: 4096                                |   |
// | - datalen: 619362                              |   |
// |------------------------------------------------| <-'
// | DESCR[0]: Sifdeffile                           |
// | - Sifcommon                                    |
// |   - datatype: DATA_DEFFILE                     |
// |   - id: 1                                      |
// |   - groupid: 1                                 |
// |   - link: NONE                                 |
// |   - fileoff: 4096                              | --.
// |   - filelen: 222                               |   |
// |------------------------------------------------| <-----.
// | DESCR[1]: Sifpartition                         |   |   |
// | - Sifcommon                                    |   |   |
// |   - datatype: DATA_PARTITION                   |   |   |
// |   - id: 2                                      |   |   |
// |   - groupid: 1                                 |   |   |
// |   - link: NONE                                 |   |   |
// |   - fileoff: 4318                              | ----. |
// |   - filelen: 618496                            |   | | |
// | - fstype: Squashfs                             |   | | |
// | - parttype: System                             |   | | |
// | - content: Linux                               |   | | |
// |------------------------------------------------|   | | |
// | DESCR[2]: Sifsignature                         |   | | |
// | - Sifcommon                                    |   | | |
// |   - datatype: DATA_SIGNATURE                   |   | | |
// |   - id: 3                                      |   | | |
// |   - groupid: NONE                              |   | | |
// |   - link: 2                                    | ------'
// |   - fileoff: 622814                            | ------.
// |   - filelen: 644                               |   | | |
// | - hashtype: SHA384                             |   | | |
// | - entity: @                                    |   | | |
// |------------------------------------------------| <-' | |
// | Definition file data                           |     | |
// | .                                              |     | |
// | .                                              |     | |
// | .                                              |     | |
// |------------------------------------------------| <---' |
// | File system partition image                    |       |
// | .                                              |       |
// | .                                              |       |
// | .                                              |       |
// |------------------------------------------------| <-----'
// | Signed verification data                       |
// | .                                              |
// | .                                              |
// | .                                              |
// `================================================'

// SIF header constants and quantities
const (
	HdrLaunch      = "#!/usr/bin/env run-singularity\n"
	HdrMagic       = "SIF_MAGIC" // SIF identification
	HdrVersion     = "0"         // SIF SPEC VERSION
	HdrArch386     = "2"         // 386 arch code
	HdrArchAMD64   = "4"         // AMD64 arch code
	HdrArchARM     = "8"         // ARM arch code
	HdrArchAARCH64 = "16"        // AARCH64 arch code

	HdrLaunchLen  = 32 // len("#!/usr/bin/env... ")
	HdrMagicLen   = 10 // len("SIF_MAGIC")
	HdrVersionLen = 3  // len("99")
	HdrArchLen    = 3  // len("99")

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

// Datatype represents the different SIF data object types stored in the image
type Datatype int32

// List of supported SIF data types
const (
	DataDeffile     Datatype = iota + 0x4001 // definition file data object
	DataEnvVar                               // environment variables data object
	DataLabels                               // JSON labels data object
	DataPartition                            // file system data object
	DataSignature                            // signing/verification data object
	DataGenericJSON                          // generic JSON meta-data
)

// Fstype represents the different SIF file system types found in partition data objects
type Fstype int32

// List of supported file systems
const (
	FsSquash  Fstype = iota + 1 // Squashfs file system, RDONLY
	FsExt3                      // EXT3 file system, RDWR (deprecated)
	FsImmuObj                   // immutable data object archive
	FsRaw                       // raw data
)

// Parttype represents the different SIF container partition types (system and data)
type Parttype int32

// List of supported partition types
const (
	PartSystem  Parttype = iota + 1 // partition hosts an operating system
	PartData                        // partition hosts data only
	PartOverlay                     // partition hosts an overlay
)

// Hashtype represents the different SIF hashing function types used to fingerprint data objects
type Hashtype int32

// List of supported hash functions
const (
	HashSHA256 Hashtype = iota + 1
	HashSHA384
	HashSHA512
	HashBLAKE2S
	HashBLAKE2B
)

// SIF data object deletation strategies
const (
	DelZero    = iota + 1 // zero the data object bytes
	DelCompact            // free the space used by data object
)

// Deffile represets the SIF definition-file data object descriptor
type Deffile struct {
}

// Labels represents the SIF JSON-labels data object descriptor
type Labels struct {
}

// Envvar represents the SIF envvar data object descriptor
type Envvar struct {
}

// Partition represents the SIF partition data object descriptor
type Partition struct {
	fstype   Fstype
	parttype Parttype
}

// Signature represents the SIF signature data object descriptor
type Signature struct {
	hashtype Hashtype
	entity   [DescrEntityLen]byte
}

// GenericJSON represents the SIF generic JSON meta-data data object descriptor
type GenericJSON struct {
}

// Descriptor represents the SIF descriptor type
type Descriptor struct {
	datatype Datatype  // informs of descriptor type
	id       uuid.UUID // a unique id for this data object
	used     bool      // is the descriptor in use
	groupid  uint32    // object group this data object is related to
	link     uint32    // special link or relation to an id or group
	fileoff  int64     // offset from start of image file
	filelen  int64     // length of data in file

	ctime   int64                 // image creation time
	mtime   int64                 // last modification time
	uid     int64                 // system user owning the file
	gid     int64                 // system group owning the file
	name    [DescrNameLen]byte    // descriptor name (string identifier)
	private [DescrMaxPrivLen]byte // big enough for above extra data
}

// Header describes a loaded SIF file
type Header struct {
	launch [HdrLaunchLen]byte // #! shell execution line

	magic   [HdrMagicLen]byte   // look for "SIF_MAGIC"
	version [HdrVersionLen]byte // SIF version
	arch    [HdrArchLen]byte    // arch the image is built for
	id      uuid.UUID           // image unique identifier

	ctime int64 // image creation time
	mtime int64 // last modification time

	dfree    int64 // # of used data object descr.
	dtotal   int64 // # of total available data object descr.
	descroff int64 // bytes into file where descs start
	descrlen int64 // bytes used by all current descriptors
	dataoff  int64 // bytes into file where data starts
	datalen  int64 // bytes used by all data objects
}

// FileImage describes the representation of a SIF file in memory
type FileImage struct {
	header    Header     // the loaded SIF global header
	nextid    int        // the next id to use for new descriptors
	fp        *os.File   // file pointer of opened SIF file
	filesize  int64      // file size of the opened SIF file
	filedata  []byte     // the content of the opened file
	descrlist *list.List // list of loaded descriptors from SIF file
}

// CreateInfo wraps all SIF file creation info needed
type CreateInfo struct {
	pathname   string     // the end result output filename
	launchstr  string     // the shell run command
	sifversion string     // the SIF specification version used
	arch       string     // the architecture targetted
	id         uuid.UUID  // image unique identifier
	inputlist  *list.List // list head of input info for descriptor creation
}

//
// This section describes SIF creation data structures used when building
// a new SIF file. Transient data not found in the final SIF file. Those data
// structures are internal.
//

// descriptorInput describes the common info needed to create a data object descriptor
type descriptorInput struct {
	datatype Datatype // datatype being harvested for new descriptor
	groupid  uint32   // group to be set for new descriptor
	link     uint32   // link to be set for new descriptor
	size     int64    // size of the data object for the new descriptor

	fname string   // file containing data associated with the new descriptor
	fp    *os.File // file pointer to opened 'fname'
	data  []byte   // loaded data from file

	image *FileImage  // loaded SIF file in memory
	descr *Descriptor // created end result descriptor

	extra bytes.Buffer // where specific input type store their data
}

// defInput describes the info needed to create an definition-file descriptor
type defInput struct {
	// nothing specific for definition-file yet
}

// envInput describes the info needed to create an env. var. descriptor
type envInput struct {
	// nothing specific for env. var. yet
}

// labelInput describes the info needed to create an label descriptor
type labelInput struct {
	// nothing specific for label yet
}

// partInput describes the info needed to create an partition descriptor
type partInput struct {
	Fstype   Fstype
	Parttype Parttype
}

// sigInput describes the info needed to create an signature descriptor
type sigInput struct {
	Hashtype Hashtype
	Entity   [DescrEntityLen]byte
}

// genJInput describes the info needed to create an generic JSON meta-data descriptor
type genJInput struct {
	// nothing specific for generic JSON meta-data yet
}
