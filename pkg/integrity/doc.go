// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

/*
Package integrity implements functions to add, examine, and verify digital signatures in a SIF
image.

Sign

To add one or more digital signatures to a SIF, create a Signer, and supply a signing PGP entity:

	s, err := integrity.NewSigner(f, OptSignWithEntity(e))

By default, the returned Signer will add one digital signature per group of objects in f. To
override this behavior, supply additional options. For example, to apply a signature to object
group 1 only:

	s, err := integrity.NewSigner(f, OptSignWithEntity(e), OptSignGroup(1))

Finally, to apply the signature(s):

	err := s.Sign()

Verify

To examine and/or verify digital signatures in a SIF, create a Verifier:

	v, err := NewVerifier(f)

If you intend to perform cryptographic verification, you must provide a source of key material:

	v, err := NewVerifier(f, OptVerifyWithKeyRing(kr))

By default, the returned Verifier will consider non-legacy signatures for all object groups. To
override this behavior, supply additional options. For example, to consider non-legacy signatures
on object group 1 only:

	v, err := NewVerifier(f, OptVerifyWithKeyRing(kr), OptVerifyGroup(1))

Finally, to perform cryptographic verification:

	err := v.Verify()
*/
package integrity
