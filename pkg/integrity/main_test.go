// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/apptainer/sif/v2/pkg/sif"
)

var corpus = filepath.Join("..", "..", "test", "images")

// fixedTime returns a fixed time value, useful for ensuring tests are deterministic.
func fixedTime() time.Time {
	return time.Unix(1504657553, 0)
}

// loadContainer loads a container from path for read-only access.
func loadContainer(t *testing.T, path string) *sif.FileImage {
	t.Helper()

	f, err := sif.LoadContainerFromPath(path, sif.OptLoadWithFlag(os.O_RDONLY))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.UnloadContainer(); err != nil {
			t.Error(err)
		}
	})

	return f
}

func getX509Signer(t *testing.T) *X509Signer {
	return &X509Signer{
		Signer:      getTestPKCS8Key(t),
		Certificate: getTextX509Certificate(t),
	}
}

func getTestPKCS8Key(t *testing.T) crypto.Signer {
	path := filepath.Join("..", "..", "test", "keys", "pkcs8.key")

	// open raw data
	rawPrivKey, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	var tryWith []byte

	// try to decode raw data as PEM
	block, _ := pem.Decode(rawPrivKey)
	if block == nil || block.Type != "PRIVATE KEY" {
		tryWith = rawPrivKey
	} else {
		tryWith = block.Bytes
	}

	// decode raw data as DER
	key, err := x509.ParsePKCS8PrivateKey(tryWith)
	if err != nil {
		t.Fatalf("failed to decode private key from '%s'", path)
	}

	return key.(crypto.Signer)
}

func getTextX509Certificate(t *testing.T) *x509.Certificate {
	path := filepath.Join("..", "..", "test", "keys", "x509.pem")

	// open raw data
	rawCert, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	var tryWith []byte

	// try to decode raw data as PEM
	block, _ := pem.Decode(rawCert)
	if block == nil || block.Type != "CERTIFICATE" {
		tryWith = rawCert
	} else {
		tryWith = block.Bytes
	}

	// decode raw data as DER
	cert, err := x509.ParseCertificate(tryWith)
	if err != nil {
		t.Fatalf("failed to decode certificate from '%s'", path)
	}

	// check validity period
	// to run tests use:
	// now, _ := time.Parse(time.RFC1123, "Mon, 02 Jan 2000 15:04:05 MST")
	now := time.Now()
	switch {
	case now.Before(cert.NotBefore):
		t.Fatalf("certificate is not yet valid")
	case now.After(cert.NotAfter):
		t.Fatalf("certificate has expired")
	}

	return cert
}

// getTestPGPEntity returns a fixed test SignPGP entity.
func getTestPGPEntity(t *testing.T) *openpgp.Entity {
	t.Helper()

	f, err := os.Open(filepath.Join("..", "..", "test", "keys", "private.asc"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	el, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(el), 1; got != want {
		t.Fatalf("got %v entities, want %v", got, want)
	}
	return el[0]
}
