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

type objectMetadata struct {
	ID               uint32  `json:"id"`
	DescriptorDigest digest  `json:"descriptorDigest"`
	ObjectDigest     *digest `json:"objectDigest,omitempty"`
}

// getObjectMetadata returns objectMetadata for object with descriptor od and content r using hash
// algorithm h.
func getObjectMetadata(od sif.Descriptor, r io.Reader, h crypto.Hash) (objectMetadata, error) {
	b := bytes.Buffer{}
	if err := writeDescriptor(&b, od); err != nil {
		return objectMetadata{}, err
	}

	// Calculate digest on object descriptor.
	d, err := newDigestReader(h, &b)
	if err != nil {
		return objectMetadata{}, err
	}
	md := objectMetadata{
		ID:               od.ID,
		DescriptorDigest: d,
	}

	// Calculate digest on object data.
	d, err = newDigestReader(h, r)
	if err != nil {
		return objectMetadata{}, err
	}
	md.ObjectDigest = &d

	return md, nil
}

type mdVersion int

const (
	metadataVersion1 mdVersion = iota + 1
)

type imageMetadata struct {
	Version mdVersion        `json:"version"`
	Header  headerMetadata   `json:"header"`
	Objects []objectMetadata `json:"objects"`
}

// getImageMetadata returns populated imageMetadata for object descriptors ods in f, using hash
// algorithm h.
func getImageMetadata(f *sif.FileImage, ods []*sif.Descriptor, h crypto.Hash) (imageMetadata, error) {
	im := imageMetadata{Version: metadataVersion1}

	// Add header metadata.
	hm, err := getHeaderMetadata(f.Header, h)
	if err != nil {
		return imageMetadata{}, err
	}
	im.Header = hm

	// Add object descriptor/data metadata.
	for _, od := range ods {
		// TODO: use something more efficient than GetData.
		r := bytes.NewReader(od.GetData(f))

		om, err := getObjectMetadata(*od, r, h)
		if err != nil {
			return imageMetadata{}, err
		}
		im.Objects = append(im.Objects, om)
	}

	return im, nil
}
