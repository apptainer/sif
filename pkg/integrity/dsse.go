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
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const metadataMediaType = "application/vnd.sylabs.sif-metadata+json"

type dsseEncoder struct {
	es          *dsse.EnvelopeSigner
	h           crypto.Hash
	payloadType string
}

// newDSSEEncoder returns an encoder that signs messages in DSSE format according to opts, with key
// material from ss. SHA256 is used as the hash algorithm, unless overridden by opts.
func newDSSEEncoder(ss []signature.Signer, opts ...signature.SignOption) (*dsseEncoder, error) {
	var so crypto.SignerOpts
	for _, opt := range opts {
		opt.ApplyCryptoSignerOpts(&so)
	}

	// If SignerOpts not explicitly supplied, set default hash algorithm.
	if so == nil {
		so = crypto.SHA256
		opts = append(opts, options.WithCryptoSignerOpts(so))
	}

	dss := make([]dsse.SignVerifier, 0, len(ss))
	for _, s := range ss {
		ds, err := newDSSESigner(s, opts...)
		if err != nil {
			return nil, err
		}

		dss = append(dss, ds)
	}

	es, err := dsse.NewEnvelopeSigner(dss...)
	if err != nil {
		return nil, err
	}

	return &dsseEncoder{
		es:          es,
		h:           so.HashFunc(),
		payloadType: metadataMediaType,
	}, nil
}

// signMessage signs the message from r in DSSE format, and writes the result to w. On success, the
// hash function is returned.
func (en *dsseEncoder) signMessage(w io.Writer, r io.Reader) (crypto.Hash, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}

	e, err := en.es.SignPayload(context.TODO(), en.payloadType, body)
	if err != nil {
		return 0, err
	}

	return en.h, json.NewEncoder(w).Encode(e)
}

type dsseDecoder struct {
	vs          []signature.Verifier
	threshold   int
	payloadType string
}

// newDSSEDecoder returns a decoder that verifies messages in DSSE format using key material from
// vs.
func newDSSEDecoder(vs ...signature.Verifier) *dsseDecoder {
	return &dsseDecoder{
		vs:          vs,
		threshold:   1, // Envelope considered verified if at least one verifier succeeds.
		payloadType: metadataMediaType,
	}
}

var (
	errDSSEVerifyEnvelopeFailed  = errors.New("dsse: verify envelope failed")
	errDSSEUnexpectedPayloadType = errors.New("unexpected DSSE payload type")
)

// verifyMessage reads a message from r, verifies its signature(s), and returns the message
// contents. On success, the accepted public keys are set in vr.
func (de *dsseDecoder) verifyMessage(r io.Reader, h crypto.Hash, vr *VerifyResult) ([]byte, error) {
	vs := make([]dsse.Verifier, 0, len(de.vs))
	for _, v := range de.vs {
		dv, err := newDSSEVerifier(v, options.WithCryptoSignerOpts(h))
		if err != nil {
			return nil, err
		}

		vs = append(vs, dv)
	}

	v, err := dsse.NewMultiEnvelopeVerifier(de.threshold, vs...)
	if err != nil {
		return nil, err
	}

	var e dsse.Envelope
	if err := json.NewDecoder(r).Decode(&e); err != nil {
		return nil, err
	}

	vr.aks, err = v.Verify(context.TODO(), &e)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errDSSEVerifyEnvelopeFailed, err)
	}

	if e.PayloadType != de.payloadType {
		return nil, fmt.Errorf("%w: %v", errDSSEUnexpectedPayloadType, e.PayloadType)
	}

	return e.DecodeB64Payload()
}

type dsseSigner struct {
	s    signature.Signer
	opts []signature.SignOption
	pub  crypto.PublicKey
}

// newDSSESigner returns a dsse.SignVerifier that uses s to sign according to opts. Note that the
// returned value is suitable only for signing, and not verification.
func newDSSESigner(s signature.Signer, opts ...signature.SignOption) (*dsseSigner, error) {
	pub, err := s.PublicKey()
	if err != nil {
		return nil, err
	}

	return &dsseSigner{
		s:    s,
		opts: opts,
		pub:  pub,
	}, nil
}

// Sign signs the supplied data.
func (s *dsseSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	opts := s.opts
	opts = append(opts, options.WithContext(ctx))

	return s.s.SignMessage(bytes.NewReader(data), opts...)
}

var errSignNotImplemented = errors.New("sign not implemented")

// Verify is not implemented, but required for the dsse.SignVerifier interface.
func (s *dsseSigner) Verify(ctx context.Context, data, sig []byte) error {
	return errSignNotImplemented
}

// Public returns the public key associated with s.
func (s *dsseSigner) Public() crypto.PublicKey {
	return s.pub
}

// KeyID returns the key ID associated with s.
func (s dsseSigner) KeyID() (string, error) {
	return dsse.SHA256KeyID(s.pub)
}

type dsseVerifier struct {
	v    signature.Verifier
	opts []signature.VerifyOption
	pub  crypto.PublicKey
}

// newDSSEVerifier returns a dsse.Verifier that uses v to verify according to opts.
func newDSSEVerifier(v signature.Verifier, opts ...signature.VerifyOption) (*dsseVerifier, error) {
	pub, err := v.PublicKey()
	if err != nil {
		return nil, err
	}

	return &dsseVerifier{
		v:    v,
		opts: opts,
		pub:  pub,
	}, nil
}

// Verify verifies that sig is a valid signature of data.
func (v *dsseVerifier) Verify(ctx context.Context, data, sig []byte) error {
	opts := v.opts
	opts = append(opts, options.WithContext(ctx))

	return v.v.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), opts...)
}

// Public returns the public key associated with v.
func (v *dsseVerifier) Public() crypto.PublicKey {
	return v.pub
}

// KeyID returns the key ID associated with v.
func (v *dsseVerifier) KeyID() (string, error) {
	return dsse.SHA256KeyID(v.pub)
}

// isDSSESignature returns true if r contains a signature in a DSSE envelope.
func isDSSESignature(r io.Reader) bool {
	var e dsse.Envelope
	if err := json.NewDecoder(r).Decode(&e); err != nil {
		return false
	}

	return metadataMediaType == e.PayloadType
}
