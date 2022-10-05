// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var errClearsignedMsgNotFound = errors.New("clearsigned message not found")

// Hash functions specified for OpenPGP in RFC4880, excluding those that are not currently
// recommended by NIST.
var supportedPGPAlgorithms = []crypto.Hash{
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
}

type clearsignEncoder struct {
	e      *openpgp.Entity
	config *packet.Config
}

// newClearsignEncoder returns an encoder that signs messages in clear-sign format using entity e. If
// timeFunc is not nil, it is used to generate signature timestamps.
func newClearsignEncoder(e *openpgp.Entity, timeFunc func() time.Time) *clearsignEncoder {
	return &clearsignEncoder{
		e: e,
		config: &packet.Config{
			Time: timeFunc,
		},
	}
}

// signMessage signs the message from r in clear-sign format, and writes the result to w. On
// success, the hash function and fingerprint of the signing key are returned.
func (s *clearsignEncoder) signMessage(w io.Writer, r io.Reader) (crypto.Hash, []byte, error) {
	plaintext, err := clearsign.Encode(w, s.e.PrivateKey, s.config)
	if err != nil {
		return 0, nil, err
	}
	defer plaintext.Close()

	_, err = io.Copy(plaintext, r)
	return s.config.Hash(), s.e.PrimaryKey.Fingerprint, err
}

// verifyAndDecodeJSON reads the first clearsigned message in data, verifies its signature, and
// returns the signing entity any suffix of data which follows the message. The plaintext is
// unmarshalled to v (if not nil).
func verifyAndDecodeJSON(data []byte, v interface{}, kr openpgp.KeyRing) (*openpgp.Entity, []byte, error) {
	// Decode clearsign block and check signature.
	e, plaintext, rest, err := verifyAndDecode(data, kr)
	if err != nil {
		return e, rest, err
	}

	// Unmarshal plaintext, if requested.
	if v != nil {
		err = json.Unmarshal(plaintext, v)
	}
	return e, rest, err
}

// verifyAndDecode reads the first clearsigned message in data, verifies its signature, and returns
// the signing entity, plaintext and suffix of data which follows the message.
func verifyAndDecode(data []byte, kr openpgp.KeyRing) (*openpgp.Entity, []byte, []byte, error) {
	// Decode clearsign block.
	b, rest := clearsign.Decode(data)
	if b == nil {
		return nil, nil, rest, errClearsignedMsgNotFound
	}

	// Check signature.
	e, err := openpgp.CheckDetachedSignatureAndHash(
		kr,
		bytes.NewReader(b.Bytes),
		b.ArmoredSignature.Body,
		supportedPGPAlgorithms,
		nil,
	)
	return e, b.Plaintext, rest, err
}

// isLegacySignature reads the first clearsigned message in data, and returns true if the plaintext
// contains a legacy signature.
func isLegacySignature(data []byte) (bool, error) {
	// Decode clearsign block.
	b, _ := clearsign.Decode(data)
	if b == nil {
		return false, errClearsignedMsgNotFound
	}

	// The plaintext of legacy signatures always begins with "SIFHASH", and non-legacy signatures
	// never do, as they are JSON.
	return bytes.HasPrefix(b.Plaintext, []byte("SIFHASH:\n")), nil
}
