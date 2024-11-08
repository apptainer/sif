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
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/apptainer/sif/v2/pkg/sif"
	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	errFingerprintMismatch          = errors.New("fingerprint in descriptor does not correspond to signing entity")
	errNonGroupedObject             = errors.New("non-signature object not associated with object group")
	errNoKeyMaterialDSSE            = errors.New("key material not provided for DSSE envelope signature")
	errNoKeyMaterialPGP             = errors.New("key material not provided for PGP clear-sign signature")
	errSignatureFormatNotRecognized = errors.New("signature format not recognized")
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
	groupID  uint32           // Object group ID.
	ods      []sif.Descriptor // Object descriptors.
	subsetOK bool             // If true, permit ods to be a subset of the objects in signatures.
}

// newGroupVerifier constructs a new group verifier, optionally limited to objects described by
// ods. If no descriptors are supplied, verify all objects in group.
func newGroupVerifier(f *sif.FileImage, groupID uint32, ods ...sif.Descriptor) (*groupVerifier, error) {
	v := groupVerifier{f: f, groupID: groupID, ods: ods}

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

// signatures returns descriptors in f that contain signature objects linked to the objects
// specified by v. If no such signatures are found, a SignatureNotFoundError is returned.
func (v *groupVerifier) signatures() ([]sif.Descriptor, error) {
	return getGroupSignatures(v.f, v.groupID, false)
}

// verifySignature performs cryptographic validation of the digital signature contained in sig
// using decoder de, populating vr as appropriate.
//
// If an invalid signature is encountered, a SignatureNotValidError is returned.
//
// If verification of the SIF global header fails, ErrHeaderIntegrity is returned. If verification
// of a data object descriptor fails, a DescriptorIntegrityError is returned. If verification of a
// data object fails, a ObjectIntegrityError is returned.
func (v *groupVerifier) verifySignature(ctx context.Context, sig sif.Descriptor, de decoder, vr *VerifyResult) error {
	ht, fp, err := sig.SignatureMetadata()
	if err != nil {
		return err
	}

	// Verify signature and decode message.
	b, err := de.verifyMessage(ctx, sig.GetReader(), ht, vr)
	if err != nil {
		return &SignatureNotValidError{ID: sig.ID(), Err: err}
	}

	// Unmarshal image metadata.
	var im imageMetadata
	if err = json.Unmarshal(b, &im); err != nil {
		return &SignatureNotValidError{ID: sig.ID(), Err: err}
	}

	// Get minimum object ID in group, and use this to populate absolute object IDs in im.
	minID, err := getGroupMinObjectID(v.f, v.groupID)
	if err != nil {
		return err
	}
	im.populateAbsoluteObjectIDs(minID)

	// Ensure signing entity matches fingerprint in descriptor.
	if e := vr.e; e != nil && !bytes.Equal(e.PrimaryKey.Fingerprint, fp) {
		return errFingerprintMismatch
	}

	// If an object subset is not permitted, verify our set of IDs match exactly what is in the
	// image metadata.
	if !v.subsetOK {
		if err := im.objectIDsMatch(v.ods); err != nil {
			return err
		}
	}

	// Verify header and object integrity.
	vr.verified, err = im.matches(v.f, v.ods)
	return err
}

type legacyGroupVerifier struct {
	f       *sif.FileImage   // SIF image to verify.
	groupID uint32           // Object group ID.
	ods     []sif.Descriptor // Object descriptors.
}

// newLegacyGroupVerifier constructs a new legacy group verifier.
func newLegacyGroupVerifier(f *sif.FileImage, groupID uint32) (*legacyGroupVerifier, error) {
	ods, err := getGroupObjects(f, groupID)
	if err != nil {
		return nil, err
	}

	return &legacyGroupVerifier{f: f, groupID: groupID, ods: ods}, nil
}

// signatures returns descriptors in f that contain signature objects linked to the objects
// specified by v. If no such signatures are found, a SignatureNotFoundError is returned.
func (v *legacyGroupVerifier) signatures() ([]sif.Descriptor, error) {
	return getGroupSignatures(v.f, v.groupID, true)
}

// verifySignature performs cryptographic validation of the digital signature contained in sig
// using decoder de, populating vr as appropriate.
//
// If an invalid signature is encountered, a SignatureNotValidError is returned.
//
// If verification of a data object fails, a ObjectIntegrityError is returned.
func (v *legacyGroupVerifier) verifySignature(ctx context.Context, sig sif.Descriptor, de decoder, vr *VerifyResult) error { //nolint:lll
	// Verify signature and decode message.
	b, err := de.verifyMessage(ctx, sig.GetReader(), crypto.SHA256, vr)
	if err != nil {
		return &SignatureNotValidError{ID: sig.ID(), Err: err}
	}

	ht, fp, err := sig.SignatureMetadata()
	if err != nil {
		return err
	}

	// Ensure signing entity matches fingerprint in descriptor.
	if e := vr.e; e != nil {
		if !bytes.Equal(e.PrimaryKey.Fingerprint, fp) {
			return errFingerprintMismatch
		}
	}

	// Obtain digest from plaintext.
	d, err := newLegacyDigest(ht, b)
	if err != nil {
		return err
	}

	// Get reader covering all non-signature objects.
	rs := make([]io.Reader, 0, len(v.ods))
	for _, od := range v.ods {
		rs = append(rs, od.GetReader())
	}
	r := io.MultiReader(rs...)

	// Verify integrity of objects.
	if ok, err := d.matches(r); err != nil {
		return err
	} else if !ok {
		return &ObjectIntegrityError{}
	}

	vr.verified = v.ods
	return nil
}

type legacyObjectVerifier struct {
	f  *sif.FileImage // SIF image to verify.
	od sif.Descriptor // Object descriptor.
}

// newLegacyObjectVerifier constructs a new legacy object verifier.
func newLegacyObjectVerifier(f *sif.FileImage, od sif.Descriptor) *legacyObjectVerifier {
	return &legacyObjectVerifier{f: f, od: od}
}

// signatures returns descriptors in f that contain signature objects linked to the objects
// specified by v. If no such signatures are found, a SignatureNotFoundError is returned.
func (v *legacyObjectVerifier) signatures() ([]sif.Descriptor, error) {
	return getObjectSignatures(v.f, v.od.ID())
}

// verifySignature performs cryptographic validation of the digital signature contained in sig
// using decoder de, populating vr as appropriate.
//
// If an invalid signature is encountered, a SignatureNotValidError is returned.
//
// If verification of a data object fails, a ObjectIntegrityError is returned.
func (v *legacyObjectVerifier) verifySignature(ctx context.Context, sig sif.Descriptor, de decoder, vr *VerifyResult) error { //nolint:lll
	// Verify signature and decode message.
	b, err := de.verifyMessage(ctx, sig.GetReader(), crypto.SHA256, vr)
	if err != nil {
		return &SignatureNotValidError{ID: sig.ID(), Err: err}
	}

	ht, fp, err := sig.SignatureMetadata()
	if err != nil {
		return err
	}

	// Ensure signing entity matches fingerprint in descriptor.
	if e := vr.e; e != nil {
		if !bytes.Equal(e.PrimaryKey.Fingerprint, fp) {
			return errFingerprintMismatch
		}
	}

	// Obtain digest from plaintext.
	d, err := newLegacyDigest(ht, b)
	if err != nil {
		return err
	}

	// Verify object integrity.
	if ok, err := d.matches(v.od.GetReader()); err != nil {
		return err
	} else if !ok {
		return &ObjectIntegrityError{ID: v.od.ID()}
	}

	vr.verified = []sif.Descriptor{v.od}
	return nil
}

type decoder interface {
	// verifyMessage reads a message from r, verifies its signature, and returns the message
	// contents.
	verifyMessage(ctx context.Context, r io.Reader, h crypto.Hash, vr *VerifyResult) ([]byte, error)
}

type verifyTask interface {
	// signatures returns descriptors that contain signature objects linked to the task. If no such
	// signatures are found, a SignatureNotFoundError is returned.
	signatures() ([]sif.Descriptor, error)

	// verifySignature performs cryptographic validation of the digital signature contained in sig
	// using decoder de, populating vr as appropriate.
	//
	// If an invalid signature is encountered, a SignatureNotValidError is returned.
	//
	// If verification of the SIF global header fails, ErrHeaderIntegrity is returned. If
	// verification of a data object descriptor fails, a DescriptorIntegrityError is returned. If
	// verification of a data object fails, a ObjectIntegrityError is returned.
	verifySignature(ctx context.Context, sig sif.Descriptor, de decoder, vr *VerifyResult) error
}

type verifyOpts struct {
	vs          []signature.Verifier
	kr          openpgp.KeyRing
	groups      []uint32
	objects     []uint32
	isLegacy    bool
	isLegacyAll bool
	ctx         context.Context //nolint:containedctx
	cb          VerifyCallback
}

// VerifierOpt are used to configure vo.
type VerifierOpt func(vo *verifyOpts) error

// OptVerifyWithVerifier appends verifier(s) to the sources of key material used for verification.
func OptVerifyWithVerifier(vs ...signature.Verifier) VerifierOpt {
	return func(vo *verifyOpts) error {
		vo.vs = append(vo.vs, vs...)
		return nil
	}
}

// OptVerifyWithKeyRing sets the keyring to use for verification to kr.
func OptVerifyWithKeyRing(kr openpgp.KeyRing) VerifierOpt {
	return func(vo *verifyOpts) error {
		vo.kr = kr
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

// OptVerifyWithContext specifies that the given context should be used in RPC to external
// services.
func OptVerifyWithContext(ctx context.Context) VerifierOpt {
	return func(vo *verifyOpts) error {
		vo.ctx = ctx
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
func getTasks(f *sif.FileImage, groupIDs, objectIDs []uint32) ([]verifyTask, error) {
	t := make([]verifyTask, 0, len(groupIDs)+len(objectIDs))

	for _, groupID := range groupIDs {
		v, err := newGroupVerifier(f, groupID)
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

		v, err := newGroupVerifier(f, od.GroupID(), od)
		if err != nil {
			return nil, err
		}
		t = append(t, v)
	}

	return t, nil
}

// getLegacyTasks returns legacy verification tasks corresponding to groupIDs and objectIDs.
func getLegacyTasks(f *sif.FileImage, groupIDs, objectIDs []uint32) ([]verifyTask, error) {
	t := make([]verifyTask, 0, len(groupIDs)+len(objectIDs))

	for _, groupID := range groupIDs {
		v, err := newLegacyGroupVerifier(f, groupID)
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

		t = append(t, newLegacyObjectVerifier(f, od))
	}

	return t, nil
}

// Verifier describes a SIF image verifier.
type Verifier struct {
	f     *sif.FileImage
	opts  verifyOpts
	tasks []verifyTask
	dsse  decoder
	cs    decoder
}

// NewVerifier returns a Verifier to examine and/or verify digital signatures(s) in f according to
// opts.
//
// Verify requires key material be provided. OptVerifyWithVerifier and/or OptVerifyWithKeyRing can
// be used for this purpose. Key material is not required for routines that do not perform
// cryptographic verification, such as AnySignedBy or AllSignedBy.
//
// By default, the returned Verifier will consider non-legacy signatures for all object groups. To
// override this behavior, consider using OptVerifyGroup, OptVerifyObject, OptVerifyLegacy, and/or
// OptVerifyLegacyAll.
func NewVerifier(f *sif.FileImage, opts ...VerifierOpt) (*Verifier, error) {
	if f == nil {
		return nil, fmt.Errorf("integrity: %w", errNilFileImage)
	}

	vo := verifyOpts{
		ctx: context.Background(),
	}

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
	t, err := getTasksFunc(f, vo.groups, vo.objects)
	if err != nil {
		return nil, fmt.Errorf("integrity: %w", err)
	}

	v := Verifier{
		f:     f,
		opts:  vo,
		tasks: t,
	}

	if vo.vs != nil {
		v.dsse = newDSSEDecoder(vo.vs...)
	}

	if vo.kr != nil {
		v.cs = newClearsignDecoder(vo.kr)
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
		sigs, err := t.signatures()
		if err != nil && !errors.Is(err, &SignatureNotFoundError{}) {
			return nil, err
		}

		fps, err := getFingerprints(sigs)
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

	slices.SortFunc(fps, bytes.Compare)

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
// If appropriate key material was not provided when v was created, Verify returns an error.
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

	// Verify signature(s) associated with each task.
	for _, t := range v.tasks {
		sigs, err := t.signatures()
		if err != nil {
			return fmt.Errorf("integrity: %w", err)
		}

		for _, sig := range sigs {
			// Get decoder based on signature type.
			var de decoder
			switch {
			case isDSSESignature(sig.GetReader()):
				if v.dsse == nil {
					return fmt.Errorf("integrity: %w", errNoKeyMaterialDSSE)
				}
				de = v.dsse
			case isClearsignSignature(sig.GetReader()):
				if v.cs == nil {
					return fmt.Errorf("integrity: %w", errNoKeyMaterialPGP)
				}
				de = v.cs
			default:
				return fmt.Errorf("integrity: %w", errSignatureFormatNotRecognized)
			}

			vr := VerifyResult{sig: sig}

			// Verify signature.
			err := t.verifySignature(v.opts.ctx, sig, de, &vr)

			// Call verify callback, if applicable.
			if v.opts.cb != nil {
				vr.err = err
				if ignoreError := v.opts.cb(vr); ignoreError {
					err = nil
				}
			}

			if err != nil {
				return fmt.Errorf("integrity: %w", err)
			}
		}
	}

	return nil
}
