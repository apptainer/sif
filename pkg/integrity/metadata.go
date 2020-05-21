// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"io"

	"github.com/sylabs/sif/pkg/sif"
)

// writeHeader writes the integrity-protected fields of h to w.
func writeHeader(w io.Writer, h sif.Header) error {
	fields := []interface{}{
		h.Launch,
		h.Magic,
		h.Version,
		h.Arch,
		h.ID,
		h.Ctime,
	}

	for _, f := range fields {
		if err := binary.Write(w, binary.LittleEndian, f); err != nil {
			return err
		}
	}
	return nil
}

// writeDescriptor writes the integrity-protected fields of od to w.
func writeDescriptor(w io.Writer, od sif.Descriptor) error {
	fields := []interface{}{
		od.Datatype,
		od.Used,
		od.ID,
		od.Groupid,
		od.Link,
		od.Filelen,
		od.Ctime,
		od.UID,
		od.Gid,
		od.Name,
		od.Extra,
	}

	for _, f := range fields {
		if err := binary.Write(w, binary.LittleEndian, f); err != nil {
			return err
		}
	}
	return nil
}

type headerMetadata struct {
	Digest digest `json:"digest"`
}

// getHeaderMetadata returns headerMetadata for hdr, using hash algorithm h.
func getHeaderMetadata(hdr sif.Header, h crypto.Hash) (headerMetadata, error) {
	b := bytes.Buffer{}
	if err := writeHeader(&b, hdr); err != nil {
		return headerMetadata{}, err
	}

	d, err := newDigestReader(h, &b)
	if err != nil {
		return headerMetadata{}, err
	}

	return headerMetadata{Digest: d}, nil
}
