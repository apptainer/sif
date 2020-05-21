// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestDigest_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		hash    crypto.Hash
		value   string
		wantErr error
	}{
		{
			name:    "UnsupportedHash",
			hash:    crypto.MD5,
			wantErr: errHashUnsupported,
		},
		{
			name:  "SHA1",
			hash:  crypto.SHA1,
			value: "597f6a540010f94c15d71806a99a2c8710e747bd",
		},
		{
			name:  "SHA224",
			hash:  crypto.SHA224,
			value: "95041dd60ab08c0bf5636d50be85fe9790300f39eb84602858a9b430",
		},
		{
			name:  "SHA256",
			hash:  crypto.SHA256,
			value: "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
		},
		{
			name:  "SHA384",
			hash:  crypto.SHA384,
			value: "6b3b69ff0a404f28d75e98a066d3fc64fffd9940870cc68bece28545b9a75086b343d7a1366838083e4b8f3ca6fd3c80",
		},
		{
			name:  "SHA512",
			hash:  crypto.SHA512,
			value: "db3974a97f2407b7cae1ae637c0030687a11913274d578492558e39c16c017de84eacdc8c62fe34ee4e12b4b1428817f09b6a2760c3f8a664ceae94d2434a593", // nolint:lll
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			value, err := hex.DecodeString(tt.value)
			if err != nil {
				t.Fatal(err)
			}

			input := digest{tt.hash, value}

			b := bytes.Buffer{}
			err = json.NewEncoder(&b).Encode(input)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if err := verifyGolden(t.Name(), &b); err != nil {
					t.Fatalf("failed to verify golden: %v", err)
				}
			}
		})
	}
}

func TestDigest_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		r         io.Reader
		wantHash  crypto.Hash
		wantValue string
		wantErr   error
	}{
		{
			name:    "Empty",
			r:       strings.NewReader(""),
			wantErr: io.EOF,
		},
		{
			name:    "MissingValue",
			r:       strings.NewReader("{}"),
			wantErr: errDigestMalformed,
		},
		{
			name:    "BadValue",
			r:       strings.NewReader(`"bad"`),
			wantErr: errDigestMalformed,
		},
		{
			name:    "UnsupportedHash",
			r:       strings.NewReader(`"md5:b0804ec967f48520697662a204f5fe72"`),
			wantErr: errHashUnsupported,
		},
		{
			name:    "DigestMalformedNotHex",
			r:       strings.NewReader(`"sha1:oops"`),
			wantErr: errDigestMalformed,
		},
		{
			name:    "DigestMalformedIncorrectLen",
			r:       strings.NewReader(`"sha1:597f"`),
			wantErr: errDigestMalformed,
		},
		{
			name:      "SHA1",
			r:         strings.NewReader(`"sha1:597f6a540010f94c15d71806a99a2c8710e747bd"`),
			wantHash:  crypto.SHA1,
			wantValue: "597f6a540010f94c15d71806a99a2c8710e747bd",
		},
		{
			name:      "SHA224",
			r:         strings.NewReader(`"sha224:95041dd60ab08c0bf5636d50be85fe9790300f39eb84602858a9b430"`),
			wantHash:  crypto.SHA1,
			wantValue: "95041dd60ab08c0bf5636d50be85fe9790300f39eb84602858a9b430",
		},
		{
			name:      "SHA256",
			r:         strings.NewReader(`"sha256:a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"`),
			wantHash:  crypto.SHA1,
			wantValue: "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
		},
		{
			name:      "SHA384",
			r:         strings.NewReader(`"sha384:6b3b69ff0a404f28d75e98a066d3fc64fffd9940870cc68bece28545b9a75086b343d7a1366838083e4b8f3ca6fd3c80"`), // nolint:lll
			wantHash:  crypto.SHA1,
			wantValue: "6b3b69ff0a404f28d75e98a066d3fc64fffd9940870cc68bece28545b9a75086b343d7a1366838083e4b8f3ca6fd3c80",
		},
		{
			name:      "SHA512",
			r:         strings.NewReader(`"sha512:db3974a97f2407b7cae1ae637c0030687a11913274d578492558e39c16c017de84eacdc8c62fe34ee4e12b4b1428817f09b6a2760c3f8a664ceae94d2434a593"`), // nolint:lll
			wantHash:  crypto.SHA1,
			wantValue: "db3974a97f2407b7cae1ae637c0030687a11913274d578492558e39c16c017de84eacdc8c62fe34ee4e12b4b1428817f09b6a2760c3f8a664ceae94d2434a593", // nolint:lll
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var d digest
			err := json.NewDecoder(tt.r).Decode(&d)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}
		})
	}
}
