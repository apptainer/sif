// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// +build mage

package main

import (
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

type gitDescription struct {
	isClean bool                // if true, the git working tree has local modifications
	ref     *plumbing.Reference // reference being described
	v       *semver.Version     // version of nearest tag reachable from ref (or nil if none found)
	n       uint64              // commits between nearest semver tag and ref (if v is non-nil)
}

// describe returns a gitDescription of ref.
func describe(r *git.Repository, ref *plumbing.Reference) (*gitDescription, error) {
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

	return &gitDescription{
		isClean: status.IsClean(),
		ref:     ref,
		v:       ver,
		n:       n,
	}, nil
}

// describeHead returns a gitDescription of HEAD.
func describeHead() (*gitDescription, error) {
	// Open git repo.
	r, err := git.PlainOpen(".")
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
