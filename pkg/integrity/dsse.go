// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2022-2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const metadataMediaType = "application/vnd.sylabs.sif-metadata+json"

type dsseEncoder struct {
	ss   []signature.Signer
	opts []signature.SignOption
}

// newDSSEEncoder returns an encoder that signs messages in DSSE format according to opts, with key
// material from ss. SHA256 is used as the hash algorithm, unless overridden by opts.
func newDSSEEncoder(ss []signature.Signer, opts ...signature.SignOption) *dsseEncoder {
	return &dsseEncoder{
		ss:   ss,
		opts: opts,
	}
}

// signMessage signs the message from r in DSSE format, and writes the result to w. On success, the
// hash function is returned.
func (en *dsseEncoder) signMessage(ctx context.Context, w io.Writer, r io.Reader) (crypto.Hash, error) {
	opts := en.opts
	opts = append(opts, options.WithContext(ctx))

	var so crypto.SignerOpts
	for _, opt := range opts {
		opt.ApplyCryptoSignerOpts(&so)
	}

	// If SignerOpts not explicitly supplied, set default hash algorithm.
	if so == nil {
		so = crypto.SHA256
		opts = append(opts, options.WithCryptoSignerOpts(so))
	}

	s := dsse.WrapMultiSigner(metadataMediaType, en.ss...)
	b, err := s.SignMessage(r, opts...)
	if err != nil {
		return 0, err
	}

	_, err = w.Write(b)
	return so.HashFunc(), err
}

type dsseDecoder struct {
	vs []signature.Verifier
}

// newDSSEDecoder returns a decoder that verifies messages in DSSE format using key material from
// vs.
func newDSSEDecoder(vs ...signature.Verifier) *dsseDecoder {
	return &dsseDecoder{
		vs: vs,
	}
}

var (
	errDSSEVerifyEnvelopeFailed  = errors.New("dsse: verify envelope failed")
	errDSSEUnexpectedPayloadType = errors.New("unexpected DSSE payload type")
)

// verifyMessage reads a message from r, verifies its signature(s), and returns the message
// contents. On success, the accepted public keys are set in vr.
func (de *dsseDecoder) verifyMessage(ctx context.Context, r io.Reader, h crypto.Hash, vr *VerifyResult) ([]byte, error) { //nolint:lll
	// Wrap the verifiers so we can accumulate the accepted public keys.
	vs := make([]signature.Verifier, 0, len(de.vs))
	for _, v := range de.vs {
		vs = append(vs, wrappedVerifier{
			Verifier: v,
			keys:     &vr.keys,
		})
	}

	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	v := dsse.WrapMultiVerifier(metadataMediaType, 1, vs...)

	if err := v.VerifySignature(bytes.NewReader(raw), nil, options.WithContext(ctx), options.WithHash(h)); err != nil {
		return nil, fmt.Errorf("%w: %w", errDSSEVerifyEnvelopeFailed, err)
	}

	var e dsseEnvelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}

	if e.PayloadType != metadataMediaType {
		return nil, fmt.Errorf("%w: %v", errDSSEUnexpectedPayloadType, e.PayloadType)
	}

	return e.DecodedPayload()
}

type wrappedVerifier struct {
	signature.Verifier
	keys *[]crypto.PublicKey
}

func (wv wrappedVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	err := wv.Verifier.VerifySignature(signature, message, opts...)
	if err == nil {
		pub, err := wv.Verifier.PublicKey()
		if err != nil {
			return err
		}

		*wv.keys = append(*wv.keys, pub)
	}
	return err
}

// dsseEnvelope describes a DSSE envelope.
type dsseEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

// DecodedPayload returns the decoded payload from envelope e.
func (e *dsseEnvelope) DecodedPayload() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return base64.URLEncoding.DecodeString(e.Payload)
	}
	return b, nil
}

// isDSSESignature returns true if r contains a signature in a DSSE envelope.
func isDSSESignature(r io.Reader) bool {
	var e dsseEnvelope
	if err := json.NewDecoder(r).Decode(&e); err != nil {
		return false
	}

	return metadataMediaType == e.PayloadType
}
