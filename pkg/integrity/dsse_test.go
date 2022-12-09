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
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sebdah/goldie/v2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func Test_dsseEncoder_signMessage(t *testing.T) {
	ed25519 := getTestSignerVerifier(t, "ed25519-private.pem")
	rsa := getTestSignerVerifier(t, "rsa-private.pem")

	tests := []struct {
		name     string
		signers  []signature.Signer
		signOpts []signature.SignOption
		wantErr  bool
		wantHash crypto.Hash
	}{
		{
			name:     "Multi",
			signers:  []signature.Signer{ed25519, rsa},
			wantHash: crypto.SHA256,
		},
		{
			name:     "ED25519",
			signers:  []signature.Signer{ed25519},
			wantHash: crypto.SHA256,
		},
		{
			name:     "RSA",
			signers:  []signature.Signer{rsa},
			wantHash: crypto.SHA256,
		},
		{
			name:    "SHA256",
			signers: []signature.Signer{rsa},
			signOpts: []signature.SignOption{
				options.WithCryptoSignerOpts(crypto.SHA256),
			},
			wantHash: crypto.SHA256,
		},
		{
			name:    "SHA384",
			signers: []signature.Signer{rsa},
			signOpts: []signature.SignOption{
				options.WithCryptoSignerOpts(crypto.SHA384),
			},
			wantHash: crypto.SHA384,
		},
		{
			name:    "SHA512",
			signers: []signature.Signer{rsa},
			signOpts: []signature.SignOption{
				options.WithCryptoSignerOpts(crypto.SHA512),
			},
			wantHash: crypto.SHA512,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}

			en, err := newDSSEEncoder(tt.signers, tt.signOpts...)
			if err != nil {
				t.Fatal(err)
			}

			ht, err := en.signMessage(&b, strings.NewReader(testMessage))
			if got, want := err, tt.wantErr; (got != nil) != want {
				t.Fatalf("got error %v, wantErr %v", got, want)
			}

			if err == nil {
				if got, want := ht, tt.wantHash; got != want {
					t.Errorf("got hash %v, want %v", got, want)
				}

				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
			}
		})
	}
}

// corruptPayloadType corrupts the payload type of e and re-signs the envelope. The result is a
// cryptographically valid envelope with an unexpected payload types.
func corruptPayloadType(t *testing.T, en *dsseEncoder, e *dsse.Envelope) {
	body, err := e.DecodeB64Payload()
	if err != nil {
		t.Fatal(err)
	}

	bad, err := en.es.SignPayload("bad", body)
	if err != nil {
		t.Fatal(err)
	}

	*e = *bad
}

// corruptPayload corrupts the payload in e. The result is that the signature(s) in e do not match
// the payload.
func corruptPayload(t *testing.T, _ *dsseEncoder, e *dsse.Envelope) {
	body, err := e.DecodeB64Payload()
	if err != nil {
		t.Fatal(err)
	}

	e.Payload = base64.StdEncoding.EncodeToString(body[:len(body)-1])
}

// corruptSignatures corrupts the signature(s) in e. The result is that the signature(s) in e do
// not match the payload.
func corruptSignatures(t *testing.T, _ *dsseEncoder, e *dsse.Envelope) {
	for i, sig := range e.Signatures {
		b, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			t.Fatal(err)
		}

		sig.Sig = base64.StdEncoding.EncodeToString(b[:len(b)-1])

		e.Signatures[i] = sig
	}
}

func Test_dsseDecoder_verifyMessage(t *testing.T) {
	ecdsa := getTestSignerVerifier(t, "ecdsa-private.pem")
	ed25519 := getTestSignerVerifier(t, "ed25519-private.pem")
	rsa := getTestSignerVerifier(t, "rsa-private.pem")

	ecdsaPub, err := ecdsa.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	ed25519Pub, err := ed25519.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	rsaPub, err := rsa.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		signers     []signature.Signer
		signOpts    []signature.SignOption
		corrupter   func(*testing.T, *dsseEncoder, *dsse.Envelope)
		de          *dsseDecoder
		wantErr     error
		wantMessage string
		wantKeys    []crypto.PublicKey
	}{
		{
			name:      "CorruptPayloadType",
			signers:   []signature.Signer{rsa},
			corrupter: corruptPayloadType,
			de:        newDSSEDecoder(rsa),
			wantErr:   errDSSEUnexpectedPayloadType,
			wantKeys:  []crypto.PublicKey{rsaPub},
		},
		{
			name:      "CorruptPayload",
			signers:   []signature.Signer{rsa},
			corrupter: corruptPayload,
			de:        newDSSEDecoder(rsa),
			wantErr:   errDSSEVerifyEnvelopeFailed,
			wantKeys:  []crypto.PublicKey{},
		},
		{
			name:      "CorruptSignatures",
			signers:   []signature.Signer{rsa},
			corrupter: corruptSignatures,
			de:        newDSSEDecoder(rsa),
			wantErr:   errDSSEVerifyEnvelopeFailed,
			wantKeys:  []crypto.PublicKey{},
		},
		{
			name:        "VerifyMulti",
			signers:     []signature.Signer{ecdsa, ed25519, rsa},
			de:          newDSSEDecoder(ecdsa, ed25519, rsa),
			wantMessage: testMessage,
			wantKeys:    []crypto.PublicKey{ecdsaPub, ed25519Pub, rsaPub},
		},
		{
			name:        "ECDSAVerifyMulti",
			signers:     []signature.Signer{ecdsa, ed25519, rsa},
			de:          newDSSEDecoder(ecdsa),
			wantMessage: testMessage,
			wantKeys:    []crypto.PublicKey{ecdsaPub},
		},
		{
			name:        "ED25519VerifyMulti",
			signers:     []signature.Signer{ecdsa, ed25519, rsa},
			de:          newDSSEDecoder(ed25519),
			wantMessage: testMessage,
			wantKeys:    []crypto.PublicKey{ed25519Pub},
		},
		{
			name:        "RSAVerifyMulti",
			signers:     []signature.Signer{ecdsa, ed25519, rsa},
			de:          newDSSEDecoder(rsa),
			wantMessage: testMessage,
			wantKeys:    []crypto.PublicKey{rsaPub},
		},
		{
			name:        "ECDSA",
			signers:     []signature.Signer{ecdsa},
			de:          newDSSEDecoder(ecdsa),
			wantMessage: testMessage,
			wantKeys:    []crypto.PublicKey{ecdsaPub},
		},
		{
			name:        "ED25519",
			signers:     []signature.Signer{ed25519},
			de:          newDSSEDecoder(ed25519),
			wantMessage: testMessage,
			wantKeys:    []crypto.PublicKey{ed25519Pub},
		},
		{
			name:        "RSA",
			signers:     []signature.Signer{rsa},
			de:          newDSSEDecoder(rsa),
			wantMessage: testMessage,
			wantKeys:    []crypto.PublicKey{rsaPub},
		},
		{
			name:    "SHA256",
			signers: []signature.Signer{rsa},
			signOpts: []signature.SignOption{
				options.WithCryptoSignerOpts(crypto.SHA256),
			},
			de:          newDSSEDecoder(rsa),
			wantMessage: testMessage,
			wantKeys:    []crypto.PublicKey{rsaPub},
		},
		{
			name:    "SHA384",
			signers: []signature.Signer{rsa},
			signOpts: []signature.SignOption{
				options.WithCryptoSignerOpts(crypto.SHA384),
			},
			de:          newDSSEDecoder(rsa),
			wantMessage: testMessage,
			wantKeys:    []crypto.PublicKey{rsaPub},
		},
		{
			name:    "SHA512",
			signers: []signature.Signer{rsa},
			signOpts: []signature.SignOption{
				options.WithCryptoSignerOpts(crypto.SHA512),
			},
			de:          newDSSEDecoder(rsa),
			wantMessage: testMessage,
			wantKeys:    []crypto.PublicKey{rsaPub},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}

			en, err := newDSSEEncoder(tt.signers, tt.signOpts...)
			if err != nil {
				t.Fatal(err)
			}

			// Sign and encode message.
			h, err := en.signMessage(&b, strings.NewReader(testMessage))
			if err != nil {
				t.Fatal(err)
			}

			// Introduce corruption, if applicable.
			if tt.corrupter != nil {
				var e dsse.Envelope
				if err := json.Unmarshal(b.Bytes(), &e); err != nil {
					t.Fatal(err)
				}

				tt.corrupter(t, en, &e)

				b.Reset()
				if err := json.NewEncoder(&b).Encode(e); err != nil {
					t.Fatal(err)
				}
			}

			// Decode and verify message.
			var vr VerifyResult
			message, err := tt.de.verifyMessage(bytes.NewReader(b.Bytes()), h, &vr)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}

			if got, want := string(message), tt.wantMessage; got != want {
				t.Errorf("got message %v, want %v", got, want)
			}

			if got, want := vr.Keys(), tt.wantKeys; !reflect.DeepEqual(got, want) {
				t.Errorf("got keys %#v, want %#v", got, want)
			}
		})
	}
}
