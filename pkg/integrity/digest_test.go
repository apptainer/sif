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
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/sebdah/goldie/v2"
)

func TestNewLegacyDigest(t *testing.T) {
	tests := []struct {
		name       string
		ht         crypto.Hash
		text       string
		wantError  error
		wantDigest digest
	}{
		{
			name:      "HashUnsupported",
			ht:        0,
			wantError: errHashUnsupported,
		},
		{
			name:      "DigestMalformed",
			ht:        crypto.SHA256,
			text:      "1234",
			wantError: errDigestMalformed,
		},
		{
			name:      "HexLength",
			ht:        crypto.SHA256,
			text:      "12345",
			wantError: hex.ErrLength,
		},
		{
			name: "SHA256",
			ht:   crypto.SHA256,
			text: "SIFHASH:\n9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n",
			wantDigest: digest{
				hash: crypto.SHA256,
				value: []byte{
					0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0,
					0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
					0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08,
				},
			},
		},
		{
			name: "SHA384",
			ht:   crypto.SHA384,
			text: "SIFHASH:\n768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9\n",
			wantDigest: digest{
				hash: crypto.SHA384,
				value: []byte{
					0x76, 0x84, 0x12, 0x32, 0x0f, 0x7b, 0x0a, 0xa5, 0x81, 0x2f, 0xce, 0x42,
					0x8d, 0xc4, 0x70, 0x6b, 0x3c, 0xae, 0x50, 0xe0, 0x2a, 0x64, 0xca, 0xa1,
					0x6a, 0x78, 0x22, 0x49, 0xbf, 0xe8, 0xef, 0xc4, 0xb7, 0xef, 0x1c, 0xcb,
					0x12, 0x62, 0x55, 0xd1, 0x96, 0x04, 0x7d, 0xfe, 0xdf, 0x17, 0xa0, 0xa9,
				},
			},
		},
		{
			name: "SHA512",
			ht:   crypto.SHA512,
			text: "SIFHASH:\nee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff\n", //nolint:lll
			wantDigest: digest{
				hash: crypto.SHA512,
				value: []byte{
					0xee, 0x26, 0xb0, 0xdd, 0x4a, 0xf7, 0xe7, 0x49, 0xaa, 0x1a, 0x8e, 0xe3,
					0xc1, 0x0a, 0xe9, 0x92, 0x3f, 0x61, 0x89, 0x80, 0x77, 0x2e, 0x47, 0x3f,
					0x88, 0x19, 0xa5, 0xd4, 0x94, 0x0e, 0x0d, 0xb2, 0x7a, 0xc1, 0x85, 0xf8,
					0xa0, 0xe1, 0xd5, 0xf8, 0x4f, 0x88, 0xbc, 0x88, 0x7f, 0xd6, 0x7b, 0x14,
					0x37, 0x32, 0xc3, 0x04, 0xcc, 0x5f, 0xa9, 0xad, 0x8e, 0x6f, 0x57, 0xf5,
					0x00, 0x28, 0xa8, 0xff,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := newLegacyDigest(tt.ht, []byte(tt.text))
			if got, want := err, tt.wantError; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if got, want := d, tt.wantDigest; !reflect.DeepEqual(got, want) {
					t.Errorf("got digest %v, want %v", got, want)
				}
			}
		})
	}
}

func TestDigest_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		hash    crypto.Hash
		value   string
		wantErr error
	}{
		{
			name:    "HashUnsupportedMD5",
			hash:    crypto.MD5,
			wantErr: errHashUnsupported,
		},
		{
			name:    "HashUnsupportedSHA1",
			hash:    crypto.SHA1,
			wantErr: errHashUnsupported,
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
			value: "db3974a97f2407b7cae1ae637c0030687a11913274d578492558e39c16c017de84eacdc8c62fe34ee4e12b4b1428817f09b6a2760c3f8a664ceae94d2434a593", //nolint:lll
		},
		{
			name:  "SHA512_224",
			hash:  crypto.SHA512_224,
			value: "06001bf08dfb17d2b54925116823be230e98b5c6c278303bc4909a8c",
		},
		{
			name:  "SHA512_256",
			hash:  crypto.SHA512_256,
			value: "3d37fe58435e0d87323dee4a2c1b339ef954de63716ee79f5747f94d974f913f",
		},
	}

	for _, tt := range tests {
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
				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
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
			name:    "HashUnsupportedMD5",
			r:       strings.NewReader(`"md5:b0804ec967f48520697662a204f5fe72"`),
			wantErr: errHashUnsupported,
		},
		{
			name:    "HashUnsupportedSHA1",
			r:       strings.NewReader(`"sha1:597f6a540010f94c15d71806a99a2c8710e747bd"`),
			wantErr: errHashUnsupported,
		},
		{
			name:    "DigestMalformedNotHex",
			r:       strings.NewReader(`"sha256:oops"`),
			wantErr: errDigestMalformed,
		},
		{
			name:    "DigestMalformedIncorrectLen",
			r:       strings.NewReader(`"sha256:597f"`),
			wantErr: errDigestMalformed,
		},
		{
			name:      "SHA224",
			r:         strings.NewReader(`"sha224:95041dd60ab08c0bf5636d50be85fe9790300f39eb84602858a9b430"`),
			wantHash:  crypto.SHA224,
			wantValue: "95041dd60ab08c0bf5636d50be85fe9790300f39eb84602858a9b430",
		},
		{
			name:      "SHA256",
			r:         strings.NewReader(`"sha256:a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"`),
			wantHash:  crypto.SHA256,
			wantValue: "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
		},
		{
			name:      "SHA384",
			r:         strings.NewReader(`"sha384:6b3b69ff0a404f28d75e98a066d3fc64fffd9940870cc68bece28545b9a75086b343d7a1366838083e4b8f3ca6fd3c80"`), //nolint:lll
			wantHash:  crypto.SHA384,
			wantValue: "6b3b69ff0a404f28d75e98a066d3fc64fffd9940870cc68bece28545b9a75086b343d7a1366838083e4b8f3ca6fd3c80",
		},
		{
			name:      "SHA512",
			r:         strings.NewReader(`"sha512:db3974a97f2407b7cae1ae637c0030687a11913274d578492558e39c16c017de84eacdc8c62fe34ee4e12b4b1428817f09b6a2760c3f8a664ceae94d2434a593"`), //nolint:lll
			wantHash:  crypto.SHA512,
			wantValue: "db3974a97f2407b7cae1ae637c0030687a11913274d578492558e39c16c017de84eacdc8c62fe34ee4e12b4b1428817f09b6a2760c3f8a664ceae94d2434a593", //nolint:lll
		},
		{
			name:      "SHA512_224",
			r:         strings.NewReader(`"sha512_224:06001bf08dfb17d2b54925116823be230e98b5c6c278303bc4909a8c"`),
			wantHash:  crypto.SHA512_224,
			wantValue: "06001bf08dfb17d2b54925116823be230e98b5c6c278303bc4909a8c",
		},
		{
			name:      "SHA512_256",
			r:         strings.NewReader(`"sha512_256:3d37fe58435e0d87323dee4a2c1b339ef954de63716ee79f5747f94d974f913f"`),
			wantHash:  crypto.SHA512_256,
			wantValue: "3d37fe58435e0d87323dee4a2c1b339ef954de63716ee79f5747f94d974f913f",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d digest

			err := json.NewDecoder(tt.r).Decode(&d)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if got, want := d.hash, tt.wantHash; got != want {
				t.Errorf("got hash %v, want %v", got, want)
			}

			if got, want := hex.EncodeToString(d.value), tt.wantValue; got != want {
				t.Errorf("got value %v, want %v", got, want)
			}
		})
	}
}
