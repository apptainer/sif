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
	"bufio"
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/sebdah/goldie/v2"
)

type testType struct {
	One int
	Two int
}

func Test_clearsignEncoder_signMessage(t *testing.T) {
	e := getTestEntity(t)

	encrypted := getTestEntity(t)
	encrypted.PrivateKey.Encrypted = true

	tests := []struct {
		name     string
		en       *clearsignEncoder
		r        io.Reader
		wantErr  bool
		wantHash crypto.Hash
	}{
		{
			name:    "EncryptedKey",
			en:      newClearsignEncoder(encrypted, fixedTime),
			r:       strings.NewReader(`{"One":1,"Two":2}`),
			wantErr: true,
		},
		{
			name:     "OK",
			en:       newClearsignEncoder(e, fixedTime),
			r:        strings.NewReader(`{"One":1,"Two":2}`),
			wantHash: crypto.SHA256,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}

			ht, err := tt.en.signMessage(&b, tt.r)
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

func TestVerifyAndDecodeJSON(t *testing.T) {
	e := getTestEntity(t)

	testValue := testType{1, 2}

	testMessage, err := json.Marshal(testValue)
	if err != nil {
		t.Fatal(err)
	}

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
		el         openpgp.EntityList
		corrupter  func(w io.Writer, s string) error
		output     interface{}
		wantErr    error
		wantEntity *openpgp.Entity
	}{
		{name: "ErrUnknownIssuer", el: openpgp.EntityList{}, wantErr: pgperrors.ErrUnknownIssuer},
		{name: "CorruptedClearsign", el: openpgp.EntityList{e}, corrupter: corruptClearsign},
		{name: "CorruptedSignature", el: openpgp.EntityList{e}, corrupter: corruptSignature},
		{name: "VerifyOnly", el: openpgp.EntityList{e}, wantEntity: e},
		{name: "DefaultHash", el: openpgp.EntityList{e}, output: &testType{}, wantEntity: e},
		{name: "SHA1", hash: crypto.SHA1, el: openpgp.EntityList{e}, wantErr: pgperrors.StructuralError("hash algorithm mismatch with cleartext message headers")}, //nolint:lll
		{name: "SHA224", hash: crypto.SHA224, el: openpgp.EntityList{e}, output: &testType{}, wantEntity: e},
		{name: "SHA256", hash: crypto.SHA256, el: openpgp.EntityList{e}, output: &testType{}, wantEntity: e},
		{name: "SHA384", hash: crypto.SHA384, el: openpgp.EntityList{e}, output: &testType{}, wantEntity: e},
		{name: "SHA512", hash: crypto.SHA512, el: openpgp.EntityList{e}, output: &testType{}, wantEntity: e},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}

			cs := clearsignEncoder{
				e: e,
				config: &packet.Config{
					DefaultHash: tt.hash,
					Time:        fixedTime,
				},
			}
			_, err := cs.signMessage(&b, bytes.NewReader(testMessage))
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

			// Verify and decode.
			e, rest, err := verifyAndDecodeJSON(b.Bytes(), tt.output, tt.el)

			// Shouldn't be any trailing bytes.
			if n := len(rest); n != 0 {
				t.Errorf("%v trailing bytes", n)
			}

			// Verify the error (if any) is appropriate.
			if tt.corrupter == nil {
				if got, want := err, tt.wantErr; !errors.Is(got, want) {
					t.Fatalf("got error %v, want %v", got, want)
				}
			} else if err == nil {
				t.Errorf("got nil error despite corruption")
			}

			if err == nil {
				if tt.output != nil {
					if got, want := tt.output, &testValue; !reflect.DeepEqual(got, want) {
						t.Errorf("got value %v, want %v", got, want)
					}
				}

				if got, want := e, tt.wantEntity; !reflect.DeepEqual(got, want) {
					t.Errorf("got entity %+v, want %+v", got, want)
				}
			}
		})
	}
}
