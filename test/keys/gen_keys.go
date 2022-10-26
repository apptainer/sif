// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func writeKeys() error {
	keys := []struct {
		path  string
		keyFn func() (crypto.PrivateKey, error)
	}{
		{
			path: "ecdsa.pem",
			keyFn: func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
		},
		{
			path: "ed25519.pem",
			keyFn: func() (crypto.PrivateKey, error) {
				_, pri, err := ed25519.GenerateKey(rand.Reader)
				return pri, err
			},
		},
		{
			path: "rsa.pem",
			keyFn: func() (crypto.PrivateKey, error) {
				return rsa.GenerateKey(rand.Reader, 4096)
			},
		},
	}

	for _, key := range keys {
		pri, err := key.keyFn()
		if err != nil {
			return err
		}

		pem, err := cryptoutils.MarshalPrivateKeyToPEM(pri)
		if err != nil {
			return err
		}

		if err := os.WriteFile(key.path, pem, 0o600); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	if err := writeKeys(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
