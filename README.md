# The Singularity Image Format (SIF)

<a href="https://circleci.com/gh/sylabs/sif"><img src="https://circleci.com/gh/sylabs/sif.svg?style=shield&circle-token=7e762a71efecb4da6cd6981e90cf4cc9c5e4291e"/></a>
<a href="https://app.zenhub.com/workspace/o/sylabs/sif/boards"><img src="https://raw.githubusercontent.com/ZenHubIO/support/master/zenhub-badge.png"></a>

SIF is an open source implementation of the Singularity Container Image Format
that makes it easy to create complete and encapsulated container environments
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

## Contributing

SIF and Singularity is the work of many contributors. We appreciate your help!

To contribute, please read the contribution guidelines:
[CONTRIBUTING.md](./CONTRIBUTING.md)
