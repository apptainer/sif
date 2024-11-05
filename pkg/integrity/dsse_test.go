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
	"reflect"
	"strings"
	"testing"

	"github.com/sebdah/goldie/v2"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func Test_dsseEncoder_signMessage(t *testing.T) {
	tests := []struct {
		name     string
		signers  []signature.Signer
		signOpts []signature.SignOption
		wantErr  bool
		wantHash crypto.Hash
	}{
		{
			name: "Multi",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			wantHash: crypto.SHA256,
		},
		{
			name: "ED25519",
			signers: []signature.Signer{
				getTestSigner(t, "ed25519-private.pem", crypto.Hash(0)),
			},
			signOpts: []signature.SignOption{
				options.WithCryptoSignerOpts(crypto.Hash(0)),
			},
			wantHash: crypto.Hash(0),
		},
		{
			name: "RSA_SHA256",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			wantHash: crypto.SHA256,
		},
		{
			name: "RSA_SHA384",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA384),
			},
			signOpts: []signature.SignOption{
				options.WithCryptoSignerOpts(crypto.SHA384),
			},
			wantHash: crypto.SHA384,
		},
		{
			name: "RSA_SHA512",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA512),
			},
			signOpts: []signature.SignOption{
				options.WithCryptoSignerOpts(crypto.SHA512),
			},
			wantHash: crypto.SHA512,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}

			en := newDSSEEncoder(tt.signers, tt.signOpts...)

			ht, err := en.signMessage(context.Background(), &b, strings.NewReader(testMessage))
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
func corruptPayloadType(t *testing.T, en *dsseEncoder, e *dsseEnvelope) {
	t.Helper()

	body, err := e.DecodedPayload()
	if err != nil {
		t.Fatal(err)
	}

	bad, err := dsse.WrapMultiSigner("bad", en.ss...).SignMessage(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(bad, e); err != nil {
		t.Fatal(err)
	}
}

// corruptPayload corrupts the payload in e. The result is that the signature(s) in e do not match
// the payload.
func corruptPayload(t *testing.T, _ *dsseEncoder, e *dsseEnvelope) {
	t.Helper()

	body, err := e.DecodedPayload()
	if err != nil {
		t.Fatal(err)
	}

	e.Payload = base64.StdEncoding.EncodeToString(body[:len(body)-1])
}

// corruptSignatures corrupts the signature(s) in e. The result is that the signature(s) in e do
// not match the payload.
func corruptSignatures(t *testing.T, _ *dsseEncoder, e *dsseEnvelope) {
	t.Helper()

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
	tests := []struct {
		name        string
		signers     []signature.Signer
		signOpts    []signature.SignOption
		corrupter   func(*testing.T, *dsseEncoder, *dsseEnvelope)
		de          *dsseDecoder
		wantErr     error
		wantMessage string
		wantKeys    []crypto.PublicKey
	}{
		{
			name: "CorruptPayloadType",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			corrupter: corruptPayloadType,
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA256),
			),
			wantErr: errDSSEUnexpectedPayloadType,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "rsa-public.pem"),
			},
		},
		{
			name: "CorruptPayload",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			corrupter: corruptPayload,
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA256),
			),
			wantErr: errDSSEVerifyEnvelopeFailed,
		},
		{
			name: "CorruptSignatures",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			corrupter: corruptSignatures,
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA256),
			),
			wantErr: errDSSEVerifyEnvelopeFailed,
		},
		{
			name: "Multi_SHA256",
			signers: []signature.Signer{
				getTestSigner(t, "ecdsa-private.pem", crypto.SHA256),
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "ecdsa-public.pem", crypto.SHA256),
				getTestVerifier(t, "rsa-public.pem", crypto.SHA256),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "ecdsa-public.pem"),
				getTestPublicKey(t, "rsa-public.pem"),
			},
		},
		{
			name: "Multi_SHA256_ECDSA",
			signers: []signature.Signer{
				getTestSigner(t, "ecdsa-private.pem", crypto.SHA256),
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "ecdsa-public.pem", crypto.SHA256),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "ecdsa-public.pem"),
			},
		},
		{
			name: "Multi_SHA256_RSA",
			signers: []signature.Signer{
				getTestSigner(t, "ecdsa-private.pem", crypto.SHA256),
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA256),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "rsa-public.pem"),
			},
		},
		{
			name: "ECDSA_SHA256",
			signers: []signature.Signer{
				getTestSigner(t, "ecdsa-private.pem", crypto.SHA256),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "ecdsa-public.pem", crypto.SHA256),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "ecdsa-public.pem"),
			},
		},
		{
			name: "ED25519",
			signers: []signature.Signer{
				getTestSigner(t, "ed25519-private.pem", crypto.Hash(0)),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "ed25519-public.pem", crypto.Hash(0)),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "ed25519-public.pem"),
			},
		},
		{
			name: "RSA_SHA256",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA256),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "rsa-public.pem"),
			},
		},
		{
			name: "RSA_SHA384",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA384),
			},
			signOpts: []signature.SignOption{
				options.WithCryptoSignerOpts(crypto.SHA384),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA384),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "rsa-public.pem"),
			},
		},
		{
			name: "RSA_SHA512",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA512),
			},
			signOpts: []signature.SignOption{
				options.WithCryptoSignerOpts(crypto.SHA512),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA512),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "rsa-public.pem"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}

			en := newDSSEEncoder(tt.signers, tt.signOpts...)

			// Sign and encode message.
			h, err := en.signMessage(context.Background(), &b, strings.NewReader(testMessage))
			if err != nil {
				t.Fatal(err)
			}

			// Introduce corruption, if applicable.
			if tt.corrupter != nil {
				var e dsseEnvelope
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
			message, err := tt.de.verifyMessage(context.Background(), bytes.NewReader(b.Bytes()), h, &vr)

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
