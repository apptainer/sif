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
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/apptainer/sif/v2/pkg/sif"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
)

var (
	errFingerprintMismatch = errors.New("fingerprint in descriptor does not correspond to signing entity")
	errNonGroupedObject    = errors.New("non-signature object not associated with object group")
)

// SignatureNotValidError records an error when an invalid signature is encountered.
type SignatureNotValidError struct {
	ID  uint32 // Signature object ID.
	Err error  // Wrapped error.
}

func (e *SignatureNotValidError) Error() string {
	b := &strings.Builder{}

	if e.ID == 0 {
		fmt.Fprintf(b, "signature not valid")
	} else {
		fmt.Fprintf(b, "signature object %v not valid", e.ID)
	}

	if e.Err != nil {
		fmt.Fprintf(b, ": %v", e.Err)
	}

	return b.String()
}

func (e *SignatureNotValidError) Unwrap() error {
	return e.Err
}

// Is compares e against target. If target is a SignatureNotValidError and matches e or target has
// a zero value ID, true is returned.
func (e *SignatureNotValidError) Is(target error) bool {
	//nolint:errorlint // don't compare wrapped errors in Is()
	t, ok := target.(*SignatureNotValidError)
	if !ok {
		return false
	}
	return e.ID == t.ID || t.ID == 0
}

// VerifyCallback is called immediately after a signature is verified. If r contains a non-nil
// error, and the callback returns true, the error is ignored, and verification proceeds as if no
// error occurred.
type VerifyCallback func(r VerifyResult) (ignoreError bool)

type groupVerifier struct {
	f        *sif.FileImage   // SIF image to verify.
	cb       VerifyCallback   // Verification callback.
	groupID  uint32           // Object group ID.
	ods      []sif.Descriptor // Object descriptors.
	subsetOK bool             // If true, permit ods to be a subset of the objects in signatures.
}

// newGroupVerifier constructs a new group verifier, optionally limited to objects described by
// ods. If no descriptors are supplied, verify all objects in group.
func newGroupVerifier(f *sif.FileImage, cb VerifyCallback, groupID uint32, ods ...sif.Descriptor) (*groupVerifier, error) { //nolint:lll
	v := groupVerifier{f: f, cb: cb, groupID: groupID, ods: ods}

	if len(ods) == 0 {
		ods, err := getGroupObjects(f, groupID)
		if err != nil {
			return nil, err
		}
		v.ods = ods
	} else {
		v.subsetOK = true
	}

	return &v, nil
}

// fingerprints returns a sorted list of unique fingerprints of entities that have signed the
// objects specified by v.
func (v *groupVerifier) fingerprints() ([][]byte, error) {
	sigs, err := getGroupSignatures(v.f, v.groupID, false)
	if errors.Is(err, &SignatureNotFoundError{}) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return getFingerprints(sigs)
}

func (v *groupVerifier) verifySignature(signer interface{}) error {
	switch s := signer.(type) {
	case openpgp.KeyRing:
		return v.verifyPGPWithKeyRing(s)
	case X509Signer:
		return v.verifyX509WithRootCA(s.Certificate)
	case *x509.Certificate:
		return v.verifyX509WithRootCA(s)
	default:
		return errors.Errorf("Unknown signer %T", signer)
	}
}

// verifyPGPSignature verifies the objects specified by v against signature sig using keyring kr.
//
// If an invalid signature is encountered, a SignatureNotValidError is returned.
//
// If verification of the SIF global header fails, ErrHeaderIntegrity is returned. If verification
// of a data object descriptor fails, a DescriptorIntegrityError is returned. If verification of a
// data object fails, a ObjectIntegrityError is returned.
func (v *groupVerifier) verifyPGPSignature(sig sif.Descriptor, kr openpgp.KeyRing) ([]sif.Descriptor, *openpgp.Entity, error) { //nolint:lll
	b, err := sig.GetData()
	if err != nil {
		return nil, nil, err
	}

	// Verify signature and decode image metadata.
	var im imageMetadata
	e, _, err := verifyAndDecodeJSON(b, &im, kr)
	if err != nil {
		return nil, e, &SignatureNotValidError{ID: sig.ID(), Err: err}
	}

	// Get minimum object ID in group, and use this to populate absolute object IDs in im.
	minID, err := getGroupMinObjectID(v.f, v.groupID)
	if err != nil {
		return nil, e, err
	}
	im.populateAbsoluteObjectIDs(minID)

	// Ensure signing entity matches fingerprint in descriptor.
	_, fp, err := sig.SignatureMetadata()
	if err != nil {
		return nil, e, err
	}
	if !bytes.Equal(e.PrimaryKey.Fingerprint, fp) {
		return nil, e, errFingerprintMismatch
	}

	// If an object subset is not permitted, verify our set of IDs match exactly what is in the
	// image metadata.
	if !v.subsetOK {
		if err := im.objectIDsMatch(v.ods); err != nil {
			return nil, e, err
		}
	}

	// Verify header and object integrity.
	verified, err := im.matches(v.f, v.ods)
	if err != nil {
		return verified, e, err
	}

	return verified, e, nil
}

// verifyPGPWithKeyRing performs verification of the objects specified by v using keyring kr.
//
// If no signatures are found for the object group specified by v, a SignatureNotFoundError is
// returned. If an invalid signature is encountered, a SignatureNotValidError is returned.
//
// If verification of the SIF global header fails, ErrHeaderIntegrity is returned. If verification
// of a data object descriptor fails, a DescriptorIntegrityError is returned. If verification of a
// data object fails, a ObjectIntegrityError is returned.
func (v *groupVerifier) verifyPGPWithKeyRing(kr openpgp.KeyRing) error {
	// Obtain all signatures related to group.
	sigs, err := getGroupSignatures(v.f, v.groupID, false)
	if err != nil {
		return err
	}

	var errors *multierror.Error
	for _, sig := range sigs {
		verified, e, err := v.verifyPGPSignature(sig, kr)

		// Call verify callback, if applicable.
		if v.cb != nil {
			r := VerifyResult{sig: sig, verified: verified, e: e, err: err}
			if ignoreError := v.cb(r); ignoreError {
				err = nil
			}
		}

		if err != nil {
			errors = multierror.Append(errors, err)
		}
	}
	return errors.ErrorOrNil()
}

func (v *groupVerifier) verifyX509Signature(sig sif.Descriptor, cert *x509.Certificate) ([]sif.Descriptor, *x509.Certificate, error) { //nolint:lll
	b, err := sig.GetData()
	if err != nil {
		return nil, nil, err
	}

	// Verify signature and decode image metadata.
	var im imageMetadata
	e, _, err := verifyX509AndDecodeJSON(b, &im, cert)
	if err != nil {
		return nil, e, &SignatureNotValidError{ID: sig.ID(), Err: err}
	}

	// Get minimum object ID in group, and use this to populate absolute object IDs in im.
	minID, err := getGroupMinObjectID(v.f, v.groupID)
	if err != nil {
		return nil, e, err
	}
	im.populateAbsoluteObjectIDs(minID)

	// Ensure signing entity matches fingerprint in descriptor.
	_, fp, err := sig.SignatureMetadata()
	if err != nil {
		return nil, e, err
	}
	if !bytes.Equal(e.SubjectKeyId, fp) {
		return nil, e, errFingerprintMismatch
	}

	// If an object subset is not permitted, verify our set of IDs match exactly what is in the
	// image metadata.
	if !v.subsetOK {
		if err := im.objectIDsMatch(v.ods); err != nil {
			return nil, e, err
		}
	}

	// Verify header and object integrity.
	verified, err := im.matches(v.f, v.ods)
	if err != nil {
		return verified, e, err
	}

	return verified, e, nil
}

func (v *groupVerifier) verifyX509WithRootCA(signer *x509.Certificate) error {
	// Obtain all signatures related to group.
	sigs, err := getGroupSignatures(v.f, v.groupID, false)
	if err != nil {
		return err
	}

	var errors *multierror.Error
	for _, sig := range sigs {
		verified, e, err := v.verifyX509Signature(sig, signer)

		// Call verify callback, if applicable.
		if v.cb != nil {
			r := VerifyResult{sig: sig, verified: verified, e: e, err: err}
			if ignoreError := v.cb(r); ignoreError {
				err = nil
			}
		}

		if err != nil {
			errors = multierror.Append(errors, err)
		}
	}
	return errors.ErrorOrNil()
}

type legacyGroupVerifier struct {
	f       *sif.FileImage   // SIF image to verify.
	cb      VerifyCallback   // Verification callback.
	groupID uint32           // Object group ID.
	ods     []sif.Descriptor // Object descriptors.
}

// newLegacyGroupVerifier constructs a new legacy group verifier.
func newLegacyGroupVerifier(f *sif.FileImage, cb VerifyCallback, groupID uint32) (*legacyGroupVerifier, error) {
	ods, err := getGroupObjects(f, groupID)
	if err != nil {
		return nil, err
	}
	return &legacyGroupVerifier{f: f, cb: cb, groupID: groupID, ods: ods}, nil
}

// fingerprints returns a sorted list of unique fingerprints of entities that have signed the
// objects specified by v.
func (v *legacyGroupVerifier) fingerprints() ([][]byte, error) {
	sigs, err := getGroupSignatures(v.f, v.groupID, true)
	if errors.Is(err, &SignatureNotFoundError{}) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return getFingerprints(sigs)
}

func (v *legacyGroupVerifier) verifySignature(signer interface{}) error {
	switch s := signer.(type) {
	case openpgp.KeyRing:
		return v.verifyPGPWithKeyRing(s)
	case X509Signer:
		return errors.Errorf("X509 method not supported for legacyGroupVerifier")
	case *x509.Certificate:
		return errors.Errorf("X509 method not supported for legacyGroupVerifier")
	default:
		return errors.Errorf("Unknown signer %T", signer)
	}
}

// verifySignature verifies the objects specified by v against signature sig using keyring kr.
//
// If an invalid signature is encountered, a SignatureNotValidError is returned.
//
// If verification of a data object fails, a ObjectIntegrityError is returned.
func (v *legacyGroupVerifier) verifyPGPSignature(sig sif.Descriptor, kr openpgp.KeyRing) (*openpgp.Entity, error) {
	b, err := sig.GetData()
	if err != nil {
		return nil, err
	}

	// Verify signature and decode plaintext.
	e, b, _, err := verifyAndDecode(b, kr)
	if err != nil {
		return e, &SignatureNotValidError{ID: sig.ID(), Err: err}
	}

	// Ensure signing entity matches fingerprint in descriptor.
	ht, fp, err := sig.SignatureMetadata()
	if err != nil {
		return e, err
	}
	if !bytes.Equal(e.PrimaryKey.Fingerprint, fp) {
		return e, errFingerprintMismatch
	}

	// Obtain digest from plaintext.
	d, err := newLegacyDigest(ht, b)
	if err != nil {
		return e, err
	}

	// Get reader covering all non-signature objects.
	rs := make([]io.Reader, 0, len(v.ods))
	for _, od := range v.ods {
		rs = append(rs, od.GetReader())
	}
	r := io.MultiReader(rs...)

	// Verify integrity of objects.
	if ok, err := d.matches(r); err != nil {
		return e, err
	} else if !ok {
		return e, &ObjectIntegrityError{}
	}

	return e, nil
}

// verifyWithKeyRing performs verification of the objects specified by v using keyring kr.
//
// If no signatures are found for the object group specified by v, a SignatureNotFoundError is
// returned. If an invalid signature is encountered, a SignatureNotValidError is returned.
//
// If verification of the data object group fails, a ObjectIntegrityError is returned.
func (v *legacyGroupVerifier) verifyPGPWithKeyRing(kr openpgp.KeyRing) error {
	// Obtain all signatures related to object.
	sigs, err := getGroupSignatures(v.f, v.groupID, true)
	if err != nil {
		return err
	}

	for _, sig := range sigs {
		e, err := v.verifyPGPSignature(sig, kr)

		// Call verify callback, if applicable.
		if v.cb != nil {
			r := VerifyResult{sig: sig, e: e, err: err}
			if err == nil {
				r.verified = v.ods
			}
			if ignoreError := v.cb(r); ignoreError {
				err = nil
			}
		}

		if err != nil {
			return err
		}
	}

	return nil
}

type legacyObjectVerifier struct {
	f  *sif.FileImage // SIF image to verify.
	cb VerifyCallback // Verification callback.
	od sif.Descriptor // Object descriptor.
}

// newLegacyObjectVerifier constructs a new legacy object verifier.
func newLegacyObjectVerifier(f *sif.FileImage, cb VerifyCallback, id uint32) (*legacyObjectVerifier, error) {
	od, err := f.GetDescriptor(sif.WithID(id))
	if err != nil {
		return nil, err
	}
	return &legacyObjectVerifier{f: f, cb: cb, od: od}, nil
}

// fingerprints returns a sorted list of unique fingerprints of entities that have signed the
// objects specified by v.
func (v *legacyObjectVerifier) fingerprints() ([][]byte, error) {
	sigs, err := getObjectSignatures(v.f, v.od.ID())
	if errors.Is(err, &SignatureNotFoundError{}) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return getFingerprints(sigs)
}

func (v *legacyObjectVerifier) verifySignature(signer interface{}) error {
	switch s := signer.(type) {
	case openpgp.KeyRing:
		return v.verifyPGPWithKeyRing(s)
	case X509Signer:
		return errors.Errorf("X509 method not supported for legacyGroupVerifier")
	case *x509.Certificate:
		return errors.Errorf("X509 method not supported for legacyObjectVerifier")
	default:
		return errors.Errorf("Unknown signer %T", signer)
	}
}

// verifyPGPSignature verifies the objects specified by v against signature sig using keyring kr.
//
// If an invalid signature is encountered, a SignatureNotValidError is returned.
//
// If verification of a data object fails, a ObjectIntegrityError is returned.
func (v *legacyObjectVerifier) verifyPGPSignature(sig sif.Descriptor, kr openpgp.KeyRing) (*openpgp.Entity, error) {
	b, err := sig.GetData()
	if err != nil {
		return nil, err
	}

	// Verify signature and decode plaintext.
	e, b, _, err := verifyAndDecode(b, kr)
	if err != nil {
		return e, &SignatureNotValidError{ID: sig.ID(), Err: err}
	}

	// Ensure signing entity matches fingerprint in descriptor.
	ht, fp, err := sig.SignatureMetadata()
	if err != nil {
		return e, err
	}
	if !bytes.Equal(e.PrimaryKey.Fingerprint, fp) {
		return e, errFingerprintMismatch
	}

	// Obtain digest from plaintext.
	d, err := newLegacyDigest(ht, b)
	if err != nil {
		return e, err
	}

	// Verify object integrity.
	if ok, err := d.matches(v.od.GetReader()); err != nil {
		return e, err
	} else if !ok {
		return e, &ObjectIntegrityError{ID: v.od.ID()}
	}

	return e, nil
}

// verifyPGPWithKeyRing performs verification of the objects specified by v using keyring kr.
//
// If no signatures are found for the object specified by v, a SignatureNotFoundError is returned.
// If an invalid signature is encountered, a SignatureNotValidError is returned.
//
// If verification of the data object fails, a ObjectIntegrityError is returned.
func (v *legacyObjectVerifier) verifyPGPWithKeyRing(kr openpgp.KeyRing) error {
	// Obtain all signatures related to object.
	sigs, err := getObjectSignatures(v.f, v.od.ID())
	if err != nil {
		return err
	}

	for _, sig := range sigs {
		e, err := v.verifyPGPSignature(sig, kr)

		// Call verify callback, if applicable.
		if v.cb != nil {
			r := VerifyResult{sig: sig, e: e, err: err}
			if err == nil {
				r.verified = []sif.Descriptor{v.od}
			}
			if ignoreError := v.cb(r); ignoreError {
				err = nil
			}
		}

		if err != nil {
			return err
		}
	}

	return nil
}

type verifyTask interface {
	fingerprints() ([][]byte, error)
	verifySignature(signer interface{}) error
}

type verifyOpts struct {
	signer      interface{}
	groups      []uint32
	objects     []uint32
	isLegacy    bool
	isLegacyAll bool
	cb          VerifyCallback
}

// VerifierOpt are used to configure vo.
type VerifierOpt func(vo *verifyOpts) error

// OptVerifyWithKeyRing sets the keyring to use for verification to kr.
func OptVerifyWithKeyRing(kr openpgp.KeyRing) VerifierOpt {
	return func(vo *verifyOpts) error {
		vo.signer = kr
		return nil
	}
}

// OptVerifyWithX509Cert sets the keyring to use for verification to kr.
func OptVerifyWithX509Cert(cert *x509.Certificate) VerifierOpt {
	return func(vo *verifyOpts) error {
		vo.signer = cert
		return nil
	}
}

// OptVerifyGroup adds a verification task for the group with the specified groupID. This may be
// called multliple times to request verification of more than one group.
func OptVerifyGroup(groupID uint32) VerifierOpt {
	return func(vo *verifyOpts) error {
		if groupID == 0 {
			return sif.ErrInvalidGroupID
		}
		vo.groups = insertSorted(vo.groups, groupID)
		return nil
	}
}

// OptVerifyObject adds a verification task for the object with the specified id. This may be
// called multliple times to request verification of more than one object.
func OptVerifyObject(id uint32) VerifierOpt {
	return func(vo *verifyOpts) error {
		if id == 0 {
			return sif.ErrInvalidObjectID
		}
		vo.objects = insertSorted(vo.objects, id)
		return nil
	}
}

// OptVerifyLegacy enables verification of legacy signatures. Non-legacy signatures will not be
// considered.
//
// Note that legacy signatures do not provide integrity protection of metadata contained in the
// global header or object descriptors. For the best security, use of non-legacy signatures is
// required.
func OptVerifyLegacy() VerifierOpt {
	return func(vo *verifyOpts) error {
		vo.isLegacy = true
		return nil
	}
}

// OptVerifyLegacyAll enables verification of legacy signatures, and adds verification tasks for
// all non-signature objects that are part of a group. Non-legacy signatures will not be
// considered.
//
// Note that legacy signatures do not provide integrity protection of metadata contained in the
// global header or object descriptors. For the best security, use of non-legacy signatures is
// required.
func OptVerifyLegacyAll() VerifierOpt {
	return func(vo *verifyOpts) error {
		vo.isLegacy = true
		vo.isLegacyAll = true
		return nil
	}
}

// OptVerifyCallback registers cb as the verification callback, which is called after each
// signature is verified.
func OptVerifyCallback(cb VerifyCallback) VerifierOpt {
	return func(vo *verifyOpts) error {
		vo.cb = cb
		return nil
	}
}

// getTasks returns verification tasks corresponding to groupIDs and objectIDs.
func getTasks(f *sif.FileImage, cb VerifyCallback, groupIDs, objectIDs []uint32) ([]verifyTask, error) {
	t := make([]verifyTask, 0, len(groupIDs)+len(objectIDs))

	for _, groupID := range groupIDs {
		v, err := newGroupVerifier(f, cb, groupID)
		if err != nil {
			return nil, err
		}
		t = append(t, v)
	}

	for _, id := range objectIDs {
		od, err := f.GetDescriptor(sif.WithID(id))
		if err != nil {
			return nil, err
		}

		v, err := newGroupVerifier(f, cb, od.GroupID(), od)
		if err != nil {
			return nil, err
		}
		t = append(t, v)
	}

	return t, nil
}

// getLegacyTasks returns legacy verification tasks corresponding to groupIDs and objectIDs.
func getLegacyTasks(f *sif.FileImage, cb VerifyCallback, groupIDs, objectIDs []uint32) ([]verifyTask, error) {
	t := make([]verifyTask, 0, len(groupIDs)+len(objectIDs))

	for _, groupID := range groupIDs {
		v, err := newLegacyGroupVerifier(f, cb, groupID)
		if err != nil {
			return nil, err
		}
		t = append(t, v)
	}

	for _, id := range objectIDs {
		v, err := newLegacyObjectVerifier(f, cb, id)
		if err != nil {
			return nil, err
		}
		t = append(t, v)
	}

	return t, nil
}

// Verifier describes a SIF image verifier.
type Verifier struct {
	f      *sif.FileImage
	signer interface{}
	tasks  []verifyTask
}

// NewVerifier returns a Verifier to examine and/or verify digital signatures(s) in f according to
// opts.
//
// Verify requires key material be provided. OptVerifyWithKeyRing can be used for this purpose. Key
// material is not required for routines that do not perform cryptographic verification, such as
// AnySignedBy or AllSignedBy.
//
// By default, the returned Verifier will consider non-legacy signatures for all object groups. To
// override this behavior, consider using OptVerifyGroup, OptVerifyObject, OptVerifyLegacy, and/or
// OptVerifyLegacyAll.
func NewVerifier(f *sif.FileImage, opts ...VerifierOpt) (*Verifier, error) {
	if f == nil {
		return nil, fmt.Errorf("integrity: %w", errNilFileImage)
	}

	vo := verifyOpts{}

	// Apply options.
	for _, o := range opts {
		if err := o(&vo); err != nil {
			return nil, fmt.Errorf("integrity: %w", err)
		}
	}

	// If "legacy all" mode selected, add all non-signature objects that are in a group.
	if vo.isLegacyAll {
		f.WithDescriptors(func(od sif.Descriptor) bool {
			if od.DataType() != sif.DataSignature && od.GroupID() != 0 {
				vo.objects = insertSorted(vo.objects, od.ID())
			}
			return false
		})
	}

	// If no verification tasks specified, add one per object group
	if len(vo.groups) == 0 && len(vo.objects) == 0 {
		ids, err := getGroupIDs(f)
		if err != nil {
			return nil, fmt.Errorf("integrity: %w", err)
		}
		vo.groups = ids
	}

	// Get tasks.
	getTasksFunc := getTasks
	if vo.isLegacy {
		getTasksFunc = getLegacyTasks
	}
	t, err := getTasksFunc(f, vo.cb, vo.groups, vo.objects)
	if err != nil {
		return nil, fmt.Errorf("integrity: %w", err)
	}

	v := Verifier{
		f:      f,
		signer: vo.signer,
		tasks:  t,
	}
	return &v, nil
}

// fingerprints returns a sorted list of unique fingerprints of entities participating in the
// verification tasks in v. If any is true, entities involved in at least one task are included.
// Otherwise, only entities participatinging in all tasks are included.
func (v *Verifier) fingerprints(any bool) ([][]byte, error) {
	m := make(map[string]int)

	// Build up a map containing fingerprints, and the number of tasks they are participating in.
	for _, t := range v.tasks {
		fps, err := t.fingerprints()
		if err != nil {
			return nil, err
		}

		for _, fp := range fps {
			m[hex.EncodeToString(fp)]++
		}
	}

	// Build up list of fingerprints.
	var fps [][]byte
	for fp, n := range m {
		if any || len(v.tasks) == n {
			b, err := hex.DecodeString(fp)
			if err != nil {
				panic(err)
			}
			fps = append(fps, b)
		}
	}

	sort.Slice(fps, func(i, j int) bool {
		return bytes.Compare(fps[i], fps[j]) < 0
	})

	return fps, nil
}

// AnySignedBy returns fingerprints for entities that have signed any of the objects specified by
// verification tasks in v.
//
// Note that this routine does not perform cryptograhic validation. To ensure the image contains
// cryptographically valid signatures, use Verify.
func (v *Verifier) AnySignedBy() ([][]byte, error) {
	fps, err := v.fingerprints(true)
	if err != nil {
		return nil, fmt.Errorf("integrity: %w", err)
	}
	return fps, nil
}

// AllSignedBy returns fingerprints for entities that have signed all of the objects specified by
// verification tasks in v.
//
// Note that this routine does not perform cryptograhic validation. To ensure the image contains
// cryptographically valid signatures, use Verify.
func (v *Verifier) AllSignedBy() ([][]byte, error) {
	fps, err := v.fingerprints(false)
	if err != nil {
		return nil, fmt.Errorf("integrity: %w", err)
	}
	return fps, nil
}

// Verify performs all cryptographic verification tasks specified by v.
//
// If key material was not provided when v was created, Verify returns an error wrapping
// ErrNoKeyMaterial.
//
// If no signatures are found for a task specified by v, an error wrapping a SignatureNotFoundError
// is returned. If an invalid signature is encountered, an error wrapping a SignatureNotValidError
// is returned.
//
// If verification of the SIF global header fails, an error wrapping ErrHeaderIntegrity is
// returned. If verification of a data object descriptor fails, an error wrapping a
// DescriptorIntegrityError is returned. If verification of a data object fails, an error wrapping
// a ObjectIntegrityError is returned.
func (v *Verifier) Verify() error {
	if v.signer == nil {
		return fmt.Errorf("integrity: %w", ErrNoKeyMaterial)
	}

	// All non-signature objects must be contained in an object group.
	ods, err := v.f.GetDescriptors(sif.WithNoGroup())
	if err != nil {
		return fmt.Errorf("integrity: %w", err)
	}
	for _, od := range ods {
		if od.DataType() != sif.DataSignature {
			return fmt.Errorf("integrity: %w", errNonGroupedObject)
		}
	}

	for _, t := range v.tasks {
		if err := t.verifySignature(v.signer); err != nil {
			return fmt.Errorf("integrity: %w", err)
		}
	}
	return nil
}
