// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.
package siftool

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/apptainer/sif/v2/internal/app/siftool"
	"github.com/apptainer/sif/v2/pkg/sif"
	"github.com/sebdah/goldie/v2"
	"github.com/spf13/cobra"
)

var corpus = filepath.Join("..", "..", "test", "images")

func makeTestSIF(t *testing.T, withDataObject bool) string {
	tf, err := os.CreateTemp("", "sif-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(tf.Name()) })
	tf.Close()

	app, err := siftool.New()
	if err != nil {
		t.Fatal(err)
	}

	if err := app.New(tf.Name()); err != nil {
		t.Fatal(err)
	}

	if withDataObject {
		err := app.Add(tf.Name(), sif.DataPartition, bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef}),
			sif.OptPartitionMetadata(sif.FsSquash, sif.PartSystem, "386"),
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	return tf.Name()
}

func runCommand(t *testing.T, cmd *cobra.Command, args []string) {
	t.Helper()

	var out, err bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&err)

	cmd.SetArgs(args)

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	g := goldie.New(t,
		goldie.WithTestNameForDir(true),
		goldie.WithSubTestNameForDir(true),
	)
	g.Assert(t, "out", out.Bytes())
	g.Assert(t, "err", err.Bytes())
}

func TestAddCommands(t *testing.T) {
	tests := []struct {
		name string
		opts []CommandOpt
		args []string
	}{
		{
			name: "SifTool",
			args: []string{"help"},
		},
		{
			name: "Add",
			args: []string{"help", "add"},
		},
		{
			name: "Del",
			args: []string{"help", "del"},
		},
		{
			name: "Dump",
			args: []string{"help", "dump"},
		},
		{
			name: "Header",
			args: []string{"help", "header"},
		},
		{
			name: "Info",
			args: []string{"help", "info"},
		},
		{
			name: "List",
			args: []string{"help", "list"},
		},
		{
			name: "New",
			args: []string{"help", "new"},
		},
		{
			name: "SetPrim",
			args: []string{"help", "setprim"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{
				Use: "siftool",
			}

			if err := AddCommands(cmd, tt.opts...); err != nil {
				t.Fatal(err)
			}

			runCommand(t, cmd, tt.args)
		})
	}
}
