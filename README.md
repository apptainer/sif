# The Singularity Image Format (SIF)

[![GoDoc](https://godoc.org/github.com/sylabs/sif?status.svg)](https://godoc.org/github.com/sylabs/sif)
[![Build Status](https://circleci.com/gh/sylabs/sif.svg?style=shield)](https://circleci.com/gh/sylabs/workflows/sif)
[![Code Coverage](https://codecov.io/gh/sylabs/sif/branch/master/graph/badge.svg)](https://codecov.io/gh/sylabs/sif)
[![Go Report Card](https://goreportcard.com/badge/github.com/sylabs/sif)](https://goreportcard.com/report/github.com/sylabs/sif)

SIF is an open source implementation of the Singularity Container Image Format
that makes it easy to create complete and encapsulated container enviroments
stored in a single file.

![SIF Image](doc/sif.png)

Unless otherwise noted, the SIF source files are distributed under the BSD-style
license found in the LICENSE.md file.

## Download and Install From Source

To get the sif package to use directly from your programs:

```sh
go get -u github.com/sylabs/sif/pkg/sif
```

To get the siftool CLI program installed to $GOPATH/bin to manipulate SIF container files:

```sh
mkdir -p $GOPATH/src/github.com/sylabs
cd $GOPATH/src/github.com/sylabs
git clone https://github.com/sylabs/sif
cd sif
./build.sh
```

### Contributing

SIF and Singularity is the work of many contributors. We appreciate your help!

To contribute, please read the contribution guidelines:
    [CONTRIBUTING.md](./CONTRIBUTING.md)
