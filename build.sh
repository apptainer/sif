#!/bin/sh -
set -e

version=`(git describe --match 'v[0-9]*' --always --dirty 2>/dev/null || \
	cat VERSION 2>/dev/null || echo "") | sed -e "s/^v//;s/-/_/g;s/_/-/;s/_/./g"`

go install -ldflags="-X main.version=$version" ./...

echo "siftool version $version built and installed in $GOPATH/bin"
