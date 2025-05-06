// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2022-2025, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package user

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var corpus = filepath.Join("..", "..", "test", "images")

func Test_Unmount(t *testing.T) {
	if _, err := exec.LookPath("squashfuse"); err != nil {
		t.Skip("squashfuse not found, skipping mount tests")
	}
	fusermountPath, err := exec.LookPath("fusermount")
	if err != nil {
		t.Skip("fusermount not found, skipping mount tests")
	}

	tests := []struct {
		name          string
		mountSIF      string
		mountPath     string
		opts          []UnmountOpt
		wantErr       bool
		wantUnmounted bool
	}{
		{
			name:          "Mounted",
			mountSIF:      filepath.Join(corpus, "one-group.sif"),
			mountPath:     t.TempDir(),
			wantErr:       false,
			wantUnmounted: true,
		},
		{
			name:      "NotMounted",
			mountSIF:  "",
			mountPath: t.TempDir(),
			wantErr:   true,
		},
		{
			name:      "NotSquashfuse",
			mountSIF:  "",
			mountPath: "/dev",
			wantErr:   true,
		},
		{
			name:      "FusermountBare",
			mountSIF:  "",
			mountPath: t.TempDir(),
			opts:      []UnmountOpt{OptUnmountFusermountPath("fusermount")},
			wantErr:   true,
		},
		{
			name:          "FusermountValid",
			mountSIF:      filepath.Join(corpus, "one-group.sif"),
			mountPath:     t.TempDir(),
			opts:          []UnmountOpt{OptUnmountFusermountPath(fusermountPath)},
			wantErr:       false,
			wantUnmounted: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mountSIF != "" {
				err := Mount(context.Background(), tt.mountSIF, tt.mountPath)
				if err != nil {
					t.Fatal(err)
				}
			}

			err := Unmount(context.Background(), tt.mountPath, tt.opts...)

			if err != nil && !tt.wantErr {
				t.Errorf("Unexpected error: %s", err)
			}
			if err == nil && tt.wantErr {
				t.Error("Unexpected success")
			}

			mounted, err := isMounted(tt.mountPath)
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantUnmounted && mounted {
				t.Errorf("Expected %s to be unmounted, but it is mounted", tt.mountPath)
			}
		})
	}
}

var errBadMountInfo = errors.New("bad mount info")

func isMounted(mountPath string) (bool, error) {
	mountPath, err := filepath.Abs(mountPath)
	if err != nil {
		return false, err
	}

	mi, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, fmt.Errorf("failed to open /proc/self/mountinfo: %w", err)
	}
	defer mi.Close()

	scanner := bufio.NewScanner(mi)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) < 5 {
			return false, fmt.Errorf("not enough mountinfo fields: %w", errBadMountInfo)
		}
		//nolint:lll
		// 1348 63 0:77 / /tmp/siftool-mount-956028386 ro,nosuid,nodev,relatime shared:646 - fuse.squashfuse squashfuse ro,user_id=1000,group_id=100
		mntTarget := fields[4]
		if mntTarget == mountPath {
			return true, nil
		}
	}
	return false, nil
}
