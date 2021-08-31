// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package git

import (
	"errors"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
)

// getVersions returns a map of commit hashes to tagged semantic versions.
func getVersions(r *git.Repository) (map[plumbing.Hash]semver.Version, error) {
	// Get a list of tags. Note that we cannot use r.TagObjects() directly, since that returns
	// objects that are not referenced (for example, deleted tags.)
	iter, err := r.Tags()
	if err != nil {
		return nil, err
	}

	// Iterate through tags, selecting those that contain a valid semantic version.
	tags := make(map[plumbing.Hash]semver.Version)
	err = iter.ForEach(func(ref *plumbing.Reference) error {
		if v, err := semver.Parse(strings.TrimPrefix(ref.Name().Short(), "v")); err == nil {
			obj, err := r.TagObject(ref.Hash())
			switch err {
			case nil:
				tags[obj.Target] = v // annotated tag
			case plumbing.ErrObjectNotFound:
				tags[ref.Hash()] = v // lightweight tag
			default:
				return err
			}
		}
		return nil
	})
	return tags, err
}

// Description describes the state of a git repository.
type Description struct {
	isClean bool                // if true, the git working tree has local modifications
	ref     *plumbing.Reference // reference being described
	v       *semver.Version     // version of nearest tag reachable from ref (or nil if none found)
	n       uint64              // commits between nearest semver tag and ref (if v is non-nil)
}

// describe returns a gitDescription of ref.
func describe(r *git.Repository, ref *plumbing.Reference) (*Description, error) {
	tags, err := getVersions(r)
	if err != nil {
		return nil, err
	}

	// Get commit log.
	logIter, err := r.Log(&git.LogOptions{
		Order: git.LogOrderCommitterTime,
		From:  ref.Hash(),
	})
	if err != nil {
		return nil, err
	}

	// Iterate through commit log until we find a matching version.
	var ver *semver.Version
	var n uint64
	err = logIter.ForEach(func(c *object.Commit) error {
		if v, ok := tags[c.Hash]; ok {
			ver = &v
			return storer.ErrStop
		}
		n++
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Get working tree status.
	w, err := r.Worktree()
	if err != nil {
		return nil, err
	}
	status, err := w.Status()
	if err != nil {
		return nil, err
	}

	return &Description{
		isClean: status.IsClean(),
		ref:     ref,
		v:       ver,
		n:       n,
	}, nil
}

// Describe returns a description of HEAD of the git repository at path.
func Describe(path string) (*Description, error) {
	// Open git repo.
	r, err := git.PlainOpen(path)
	if err != nil {
		return nil, err
	}

	// Get HEAD commit.
	head, err := r.Head()
	if err != nil {
		return nil, err
	}

	return describe(r, head)
}

// IsClean returns true if the git working tree has local modifications.
func (d *Description) IsClean() bool {
	return d.isClean
}

// Reference returns the reference described by d.
func (d *Description) Reference() *plumbing.Reference {
	return d.ref
}

// Version returns a semantic version based on d. If d is tagged directly, the parsed version is
// returned. Otherwise, a version is derived that preserves semantic precedence.
//
// For example:
//  - If d.tag.Name = "v0.1.2-alpha.1" and d.n = 1, 0.1.2-alpha.1.0.devel.1 is returned.
//  - If d.tag.Name = "v0.1.2" and d.n = 1, 0.1.3-0.devel.1 is returned.
//  - If d.tag.Name = "v0.1.3" and d.n = 0, 0.1.3 is returned.
func (d *Description) Version() (semver.Version, error) {
	if d.v == nil {
		return semver.Version{}, errors.New("no semver tags found")
	}

	// If this version wasn't tagged directly, modify tag.
	v := *d.v
	if d.n > 0 {
		if len(v.Pre) == 0 {
			v.Patch++
		}

		// Append "0.devel.N" pre-release components.
		v.Pre = append(v.Pre,
			semver.PRVersion{VersionNum: 0, IsNum: true},
			semver.PRVersion{VersionStr: "devel"},
			semver.PRVersion{VersionNum: d.n, IsNum: true},
		)
	}

	return v, nil
}
