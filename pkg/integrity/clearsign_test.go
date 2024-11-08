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
	"bufio"
	"bytes"
	"context"
	"crypto"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var testMessage = `{"One":1,"Two":2}
`

func Test_clearsignEncoder_signMessage(t *testing.T) {
	e := getTestEntity(t)

	encrypted := getTestEntity(t)
	encrypted.PrivateKey.Encrypted = true

	tests := []struct {
		name     string
		en       *clearsignEncoder
		de       *clearsignDecoder
		wantErr  bool
		wantHash crypto.Hash
	}{
		{
			name:    "EncryptedKey",
			en:      newClearsignEncoder(encrypted, fixedTime),
			wantErr: true,
		},
		{
			name:     "OK",
			en:       newClearsignEncoder(e, fixedTime),
			de:       newClearsignDecoder(openpgp.EntityList{e}),
			wantHash: crypto.SHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}

			ht, err := tt.en.signMessage(context.Background(), &b, strings.NewReader(testMessage))
			if got, want := err, tt.wantErr; (got != nil) != want {
				t.Fatalf("got error %v, wantErr %v", got, want)
			}

			if err == nil {
				if got, want := ht, tt.wantHash; got != want {
					t.Errorf("got hash %v, want %v", got, want)
				}

				var vr VerifyResult
				b, err := tt.de.verifyMessage(context.Background(), bytes.NewReader(b.Bytes()), ht, &vr)
				if err != nil {
					t.Fatal(err)
				}

				if got, want := string(b), testMessage; got != want {
					t.Errorf("got message '%v', want '%v'", got, want)
				}
			}
		})
	}
}

func Test_clearsignDecoder_verifyMessage(t *testing.T) {
	e := getTestEntity(t)

	// This is used to corrupt the plaintext.
	corruptClearsign := func(w io.Writer, s string) error {
		_, err := strings.NewReplacer(`{"One":1,"Two":2}`, `{"One":2,"Two":4}`).WriteString(w, s)
		return err
	}

	// This is used to corrupt the signature.
	corruptSignature := func(w io.Writer, s string) error {
		sc := bufio.NewScanner(strings.NewReader(s))

		for sigFound, n := false, 0; sc.Scan(); {
			line := sc.Text()

			if sigFound {
				if n == 1 {
					// Introduce some corruption
					line = line[:len(line)-1]
				}
				n++
			} else if line == "-----BEGIN PGP SIGNATURE-----" {
				sigFound = true
			}

			if _, err := io.WriteString(w, line+"\n"); err != nil {
				return err
			}
		}

		return nil
	}

	tests := []struct {
		name       string
		hash       crypto.Hash
		corrupter  func(w io.Writer, s string) error
		de         *clearsignDecoder
		wantErr    error
		wantEntity *openpgp.Entity
	}{
		{
			name:    "UnknownIssuer",
			de:      newClearsignDecoder(openpgp.EntityList{}),
			wantErr: pgperrors.ErrUnknownIssuer,
		},
		{
			name:      "CorruptedClearsign",
			corrupter: corruptClearsign,
			de:        newClearsignDecoder(openpgp.EntityList{e}),
			wantErr:   pgperrors.SignatureError("RSA verification failure"),
		},
		{
			name:      "CorruptedSignature",
			corrupter: corruptSignature,
			de:        newClearsignDecoder(openpgp.EntityList{e}),
			wantErr:   pgperrors.StructuralError("signature subpacket truncated"),
		},
		{
			name:       "DefaultHash",
			de:         newClearsignDecoder(openpgp.EntityList{e}),
			wantEntity: e,
		},
		{
			name:       "SHA224",
			hash:       crypto.SHA224,
			de:         newClearsignDecoder(openpgp.EntityList{e}),
			wantEntity: e,
		},
		{
			name:       "SHA256",
			hash:       crypto.SHA256,
			de:         newClearsignDecoder(openpgp.EntityList{e}),
			wantEntity: e,
		},
		{
			name:       "SHA384",
			hash:       crypto.SHA384,
			de:         newClearsignDecoder(openpgp.EntityList{e}),
			wantEntity: e,
		},
		{
			name:       "SHA512",
			hash:       crypto.SHA512,
			de:         newClearsignDecoder(openpgp.EntityList{e}),
			wantEntity: e,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}

			// Sign and encode message.
			en := clearsignEncoder{
				e: e,
				config: &packet.Config{
					DefaultHash: tt.hash,
					Time:        fixedTime,
				},
			}
			h, err := en.signMessage(context.Background(), &b, strings.NewReader(testMessage))
			if err != nil {
				t.Fatal(err)
			}

			// Introduce corruption, if applicable.
			if tt.corrupter != nil {
				s := b.String()
				b.Reset()
				if err := tt.corrupter(&b, s); err != nil {
					t.Fatal(err)
				}
			}

			// Decode and verify message.
			var vr VerifyResult
			message, err := tt.de.verifyMessage(context.Background(), bytes.NewReader(b.Bytes()), h, &vr)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := string(message), testMessage; got != want {
					t.Errorf("got message %v, want %v", got, want)
				}

				if got, want := vr.e, tt.wantEntity; !reflect.DeepEqual(got, want) {
					t.Errorf("got entity %+v, want %+v", got, want)
				}
			}
		})
	}
}
