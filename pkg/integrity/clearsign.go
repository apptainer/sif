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

// hashAlgorithmSupported returns whether h is a supported PGP hash function.
func hashAlgorithmSupported(h crypto.Hash) bool {
	for _, alg := range supportedPGPAlgorithms {
		if alg == h {
			return true
		}
	}
	return false
}

// signAndEncodeJSON encodes v, clear-signs it with privateKey, and writes it to w. If config is
// nil, sensible defaults are used.
func signAndEncodeJSON(w io.Writer, v interface{}, privateKey *packet.PrivateKey, config *packet.Config) error {
	if !hashAlgorithmSupported(config.Hash()) {
		return errHashUnsupported
	}

	// Get clearsign encoder.
	plaintext, err := clearsign.Encode(w, privateKey, config)
	if err != nil {
		return err
	}
	defer plaintext.Close()

	// Wrap clearsign encoder with JSON encoder.
	return json.NewEncoder(plaintext).Encode(v)
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
	// Try to decode as X509
	if msg, sig, _, err := extractMsgAndX509Signature(data); err == nil && msg != nil && sig != nil {
		return false, nil
	}

	// Try to decode as PGP clearsign block
	b, _ := clearsign.Decode(data)
	if b == nil {
		return false, errClearsignedMsgNotFound
	}

	// The plaintext of legacy signatures always begins with "SIFHASH", and non-legacy signatures
	// never do, as they are JSON.
	return bytes.HasPrefix(b.Plaintext, []byte("SIFHASH:\n")), nil
}
