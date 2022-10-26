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
	"crypto"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/apptainer/sif/v2/pkg/sif"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
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

// getTestSignerVerifier returns a SignerVerifier read from the PEM file at path.
func getTestSignerVerifier(t *testing.T, name string) signature.SignerVerifier { //nolint:ireturn
	t.Helper()

	path := filepath.Join("..", "..", "test", "keys", name)

	sv, err := signature.LoadSignerVerifierFromPEMFile(path, crypto.SHA256, cryptoutils.SkipPassword)
	if err != nil {
		t.Fatal(err)
	}

	return sv
}

// getTestEntity returns a fixed test PGP entity.
func getTestEntity(t *testing.T) *openpgp.Entity {
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
