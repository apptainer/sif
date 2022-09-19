// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
	"io"
)

var errClearsignedMsgNotFound = errors.New("clearsigned message not found")

// signPGPAndEncodeJSON encodes v, clear-signs it with privateKey, and writes it to w. If config is
// nil, sensible defaults are used.
func signPGPAndEncodeJSON(w io.Writer, v interface{}, privateKey *packet.PrivateKey, config *packet.Config) error {
	// Get clearsign encoder.
	plaintext, err := clearsign.Encode(w, privateKey, config)
	if err != nil {
		return err
	}
	defer plaintext.Close()

	// Wrap clearsign encoder with JSON encoder.
	return json.NewEncoder(plaintext).Encode(v)
}

// verifyPGPAndDecodeJSON reads the first clearsigned message in data, verifies its signature, and
// returns the signing entity any suffix of data which follows the message. The plaintext is
// unmarshalled to v (if not nil).
func verifyPGPAndDecodeJSON(data []byte, v interface{}, kr openpgp.KeyRing) (*openpgp.Entity, []byte, error) {
	// Decode clearsign block and check signature.
	e, plaintext, rest, err := verifyPGPAndDecode(data, kr)
	if err != nil {
		return e, rest, err
	}

	// Unmarshal plaintext, if requested.
	if v != nil {
		err = json.Unmarshal(plaintext, v)
	}
	return e, rest, err
}

// verifyPGPAndDecode reads the first clearsigned message in data, verifies its signature, and returns
// the signing entity, plaintext and suffix of data which follows the message.
func verifyPGPAndDecode(data []byte, kr openpgp.KeyRing) (*openpgp.Entity, []byte, []byte, error) {
	// Decode clearsign block.
	b, rest := clearsign.Decode(data)
	if b == nil {
		return nil, nil, rest, errClearsignedMsgNotFound
	}

	// Check signature.
	e, err := openpgp.CheckDetachedSignature(kr, bytes.NewReader(b.Bytes), b.ArmoredSignature.Body, nil)
	return e, b.Plaintext, rest, err
}

// signX509AndEncodeJSON encodes v, clear-signs it with privateKey, and writes it to w. If config is
// nil, sensible defaults are used.
func signX509AndEncodeJSON(w io.Writer, v interface{}, signer *X509Signer) error {

	/* Create Message */
	message, err := json.Marshal(v)
	if err != nil {
		return errors.Wrap(err, "create message")
	}

	if err := pem.Encode(w, &pem.Block{Type: "SIGNED MESSAGE", Bytes: message}); err != nil {
		return errors.Wrap(err, "cannot encode PEM")
	}

	/* Create Signature */
	d := crypto.SHA256.New()
	d.Write(message)

	var signerOpts crypto.SignerOpts

	switch signer.Certificate.PublicKeyAlgorithm {
	case x509.Ed25519: // https://pkg.go.dev/crypto/ed25519#PrivateKey.Sign
		signerOpts = crypto.Hash(0)
	default:
		signerOpts = crypto.SHA256
	}

	signature, err := signer.Signer.Sign(cryptorand.Reader, d.Sum(nil), signerOpts)
	if err != nil {
		return errors.Wrap(err, "signing error")
	}

	if err := pem.Encode(w, &pem.Block{Type: "SIGNATURE", Bytes: signature}); err != nil {
		return errors.Wrap(err, "cannot encode PEM")
	}

	return nil
}

// verifyX509AndDecodeJSON reads the first clearsigned message in data, verifies its signature, and returns
// the signing entity, plaintext and suffix of data which follows the message.
func verifyX509AndDecodeJSON(data []byte, v interface{}, cert *x509.Certificate) (*x509.Certificate, []byte, error) {
	// Decode clearsign block and check signature.
	e, plaintext, rest, err := verifyX509AndDecode(data, cert)
	if err != nil {
		return e, rest, err
	}

	// Unmarshal plaintext, if requested.
	if v != nil {
		err = json.Unmarshal(plaintext, v)
	}
	return e, rest, err
}

// verifyX509AndDecode reads the first clearsigned message in data, verifies its signature, and returns
// the signing entity, plaintext and suffix of data which follows the message.
func verifyX509AndDecode(data []byte, cert *x509.Certificate) (*x509.Certificate, []byte, []byte, error) {
	if cert == nil {
		return nil, nil, nil, x509.UnknownAuthorityError{}
	}

	/* Extract Message */
	message, rest := pem.Decode(data)
	if message == nil {
		return nil, nil, rest, errClearsignedMsgNotFound
	}

	/* Extract Signature */
	signature, rest := pem.Decode(rest)
	if signature == nil {
		return nil, nil, rest, errClearsignedMsgNotFound
	}

	/* Check Signature */
	expect := crypto.SHA256.New()
	expect.Write(message.Bytes)

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		key := cert.PublicKey.(*rsa.PublicKey)

		err := rsa.VerifyPKCS1v15(key, crypto.SHA256, expect.Sum(nil)[:], signature.Bytes)
		return cert, message.Bytes, rest, errors.Wrap(err, "rsa verification error")

	case x509.ECDSA:
		key := cert.PublicKey.(*ecdsa.PublicKey)

		var err error
		if !ecdsa.VerifyASN1(key, expect.Sum(nil)[:], signature.Bytes) {
			err = errors.Errorf("verify function returned false")
		}

		return cert, message.Bytes, rest, errors.Wrap(err, "ecdsa verification error")
	case x509.Ed25519:
		key := cert.PublicKey.(*ed25519.PublicKey)

		var err error
		if !ed25519.Verify(*key, expect.Sum(nil)[:], signature.Bytes) {
			err = errors.Errorf("verify function returned false")
		}

		return cert, message.Bytes, rest, errors.Wrap(err, "ed25519 verification error")

	default:
		return nil, nil, nil, errors.Errorf("Algorithm %s is not supported", cert.PublicKeyAlgorithm.String())
	}
}

// isLegacySignature reads the first clearsigned message in data, and returns true if the plaintext
// contains a legacy signature.
func isLegacySignature(data []byte) (bool, error) {
	// Try to decode PGP
	b, _ := clearsign.Decode(data)
	if b == nil {
		return false, errClearsignedMsgNotFound
	}

	// The plaintext of legacy signatures always begins with "SIFHASH", and non-legacy signatures
	// never do, as they are JSON.
	return bytes.HasPrefix(b.Plaintext, []byte("SIFHASH:\n")), nil
}
