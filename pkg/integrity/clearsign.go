// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var errClearsignedMsgNotFound = errors.New("clearsigned message not found")

type clearsignEncoder struct {
	e      *openpgp.Entity
	config *packet.Config
}

// newClearsignEncoder returns an encoder that signs messages in clear-sign format using entity e.
// If timeFunc is not nil, it is used to generate signature timestamps.
func newClearsignEncoder(e *openpgp.Entity, timeFunc func() time.Time) *clearsignEncoder {
	return &clearsignEncoder{
		e: e,
		config: &packet.Config{
			Time: timeFunc,
		},
	}
}

// signMessage signs the message from r in clear-sign format, and writes the result to w. On
// success, the hash function is returned.
func (en *clearsignEncoder) signMessage(ctx context.Context, w io.Writer, r io.Reader) (crypto.Hash, error) {
	plaintext, err := clearsign.Encode(w, en.e.PrivateKey, en.config)
	if err != nil {
		return 0, err
	}
	defer plaintext.Close()

	_, err = io.Copy(plaintext, r)
	return en.config.Hash(), err
}

type clearsignDecoder struct {
	kr openpgp.KeyRing
}

// newClearsignDecoder returns a decoder that verifies messages in clear-sign format using key
// material from kr.
func newClearsignDecoder(kr openpgp.KeyRing) *clearsignDecoder {
	return &clearsignDecoder{
		kr: kr,
	}
}

// verifyMessage reads a message from r, verifies its signature, and returns the message contents.
// On success, the signing entity is set in vr.
func (de *clearsignDecoder) verifyMessage(ctx context.Context, r io.Reader, h crypto.Hash, vr *VerifyResult) ([]byte, error) { //nolint:lll
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Decode clearsign block.
	b, _ := clearsign.Decode(data)
	if b == nil {
		return nil, errClearsignedMsgNotFound
	}

	// Hash functions specified for OpenPGP in RFC4880, excluding those that are not currently
	// recommended by NIST.
	expectedHashes := []crypto.Hash{
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
	}

	// Check signature.
	vr.e, err = openpgp.CheckDetachedSignatureAndHash(
		de.kr,
		bytes.NewReader(b.Bytes),
		b.ArmoredSignature.Body,
		expectedHashes,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return b.Plaintext, err
}

// isClearsignSignature returns true if r contains a signature in clearsign format.
func isClearsignSignature(r io.Reader) bool {
	b, err := io.ReadAll(r)
	if err != nil {
		return false
	}

	p, _ := clearsign.Decode(b)
	return p != nil
}
