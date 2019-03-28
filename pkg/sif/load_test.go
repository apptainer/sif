// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestLoadContainer(t *testing.T) {
	fimg, err := LoadContainer("testdata/testcontainer2.sif", true)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer2.sif, true):", err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error("fimg.UnloadContainer():", err)
	}
}

func TestLoadContainerFp(t *testing.T) {
	fp, err := os.Open("testdata/testcontainer2.sif")
	if err != nil {
		t.Error("error opening testdata/testcontainer2.sif:", err)
	}

	fimg, err := LoadContainerFp(fp, true)
	if err != nil {
		t.Error("LoadContainerFp(fp, true):", err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error("fimg.UnloadContainer():", err)
	}
}

type mockFileInfo struct {
	name string
	size int64
	time time.Time
}

func (m *mockFileInfo) Name() string {
	return m.name
}

func (m *mockFileInfo) Size() int64 {
	return m.size
}

func (m *mockFileInfo) Mode() os.FileMode {
	return 0644
}

func (m *mockFileInfo) ModTime() time.Time {
	return m.time
}

func (m *mockFileInfo) IsDir() bool {
	return false
}

func (m *mockFileInfo) Sys() interface{} {
	return nil
}

type mockSifReadWriter struct {
	buf    []byte
	name   string
	pos    int64
	closed bool
}

func (m *mockSifReadWriter) Name() string {
	return m.name
}

func (m *mockSifReadWriter) Close() error {
	m.closed = true
	return nil
}

func (m *mockSifReadWriter) Fd() uintptr {
	return ^uintptr(0)
}

func (m *mockSifReadWriter) Read(b []byte) (n int, err error) {
	if m.closed {
		return 0, os.ErrInvalid
	}

	if m.pos >= int64(len(m.buf)) {
		return 0, io.EOF
	}

	n = copy(b, m.buf[m.pos:])

	m.pos += int64(n)

	return n, err
}

func (m *mockSifReadWriter) Seek(offset int64, whence int) (ret int64, err error) {
	if m.closed {
		return 0, os.ErrInvalid
	}

	sz := int64(len(m.buf))

	switch whence {
	case 0:
		ret = offset

	case 1:
		ret = offset + m.pos

	case 2:
		ret = offset + sz

	default:
		return 0, os.ErrInvalid
	}

	if ret < 0 {
		ret = 0
	} else if ret > sz {
		ret = sz
	}

	m.pos = ret

	return ret, err
}

func (m *mockSifReadWriter) Stat() (os.FileInfo, error) {
	return &mockFileInfo{name: m.name, size: int64(len(m.buf)), time: time.Unix(0, 0)}, nil
}

func (m *mockSifReadWriter) Sync() error {
	return nil
}

func (m *mockSifReadWriter) Truncate(size int64) error {
	m.pos = 0
	return nil
}

func (m *mockSifReadWriter) Write(b []byte) (n int, err error) {
	if m.closed {
		return 0, os.ErrInvalid
	}

	if len(b) > cap(m.buf[m.pos:]) {
		buf := make([]byte, 0, m.pos+int64(len(b)))
		copy(buf, m.buf)
		m.buf = buf
	}

	n = copy(m.buf[m.pos:], b)

	m.pos += int64(n)

	return n, err
}

func TestLoadContainerFpMock(t *testing.T) {
	// This test is using mockSifReadWriter to verify that the code
	// is not making assumptions regading the behavior of the
	// ReadWriter it's getting, as mockSifReadWriter implements a
	// very dumb buffer. This specific test could be exteded to test
	// for more error conditions as it would be possible to report
	// errors from cases where it would be otherwise hard to do so
	// (e.g. Seek, Read, Sync or Truncate reporting errors).

	// Load a valid SIF file to test the happy path.
	content, err := ioutil.ReadFile("testdata/testcontainer2.sif")
	if err != nil {
		t.Error(`ioutil.ReadFile("testdata/testcontainer2.sif"):`, err)
	}

	fp := &mockSifReadWriter{
		buf:  content,
		name: "mockSifReadWriter",
	}

	fimg, err := LoadContainerFp(fp, true)
	if err != nil {
		t.Error("LoadContainerFp(fp, true):", err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error("fimg.UnloadContainer():", err)
	}
}

func TestLoadContainerReader(t *testing.T) {
	content, err := ioutil.ReadFile("testdata/testcontainer2.sif")
	if err != nil {
		t.Error(`ioutil.ReadFile("testdata/testcontainer2.sif"):`, err)
	}

	// short read on the descriptor list, make sure it still work
	// and that DescrArr is set to nil (since not complete)
	r := bytes.NewReader(content[:31768])
	fimg, err := LoadContainerReader(r)
	if err != nil || fimg.DescrArr != nil {
		t.Error(`LoadContainerBuffer(buf):`, err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error(`fimg.UnloadContainer():`, err)
	}

	// this buffer is big enough to include header + complete DescrArr
	r = bytes.NewReader(content[:32768])
	fimg, err = LoadContainerReader(r)
	if err != nil {
		t.Error(`LoadContainerBuffer(buf):`, err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error(`fimg.UnloadContainer():`, err)
	}
}
