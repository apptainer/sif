// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2022-2023, Sylabs Inc. All rights reserved.
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
		pubPath string
		priPath string
		keyFn   func() (crypto.PublicKey, crypto.PrivateKey, error)
	}{
		{
			pubPath: "ecdsa-public.pem",
			priPath: "ecdsa-private.pem",
			keyFn: func() (crypto.PublicKey, crypto.PrivateKey, error) {
				pri, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, nil, err
				}
				return pri.Public(), pri, nil
			},
		},
		{
			pubPath: "ed25519-public.pem",
			priPath: "ed25519-private.pem",
			keyFn: func() (crypto.PublicKey, crypto.PrivateKey, error) {
				return ed25519.GenerateKey(rand.Reader)
			},
		},
		{
			pubPath: "rsa-public.pem",
			priPath: "rsa-private.pem",
			keyFn: func() (crypto.PublicKey, crypto.PrivateKey, error) {
				pri, err := rsa.GenerateKey(rand.Reader, 4096)
				if err != nil {
					return nil, nil, err
				}
				return pri.Public(), pri, nil
			},
		},
	}

	for _, key := range keys {
		pub, pri, err := key.keyFn()
		if err != nil {
			return err
		}

		pem, err := cryptoutils.MarshalPublicKeyToPEM(pub)
		if err != nil {
			return err
		}

		if err := os.WriteFile(key.pubPath, pem, 0o600); err != nil {
			return err
		}

		if pem, err = cryptoutils.MarshalPrivateKeyToPEM(pri); err != nil {
			return err
		}

		if err := os.WriteFile(key.priPath, pem, 0o600); err != nil {
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
