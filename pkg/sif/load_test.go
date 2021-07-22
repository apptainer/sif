// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
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
	tests := []struct {
		name   string
		offset int64
	}{
		{
			name: "NoSeek",
		},
		{
			name:   "Seek",
			offset: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp, err := os.Open("testdata/testcontainer2.sif")
			if err != nil {
				t.Fatal("error opening testdata/testcontainer2.sif:", err)
			}

			if _, err := fp.Seek(tt.offset, io.SeekStart); err != nil {
				t.Fatal(err)
			}

			fimg, err := LoadContainerFp(fp, true)
			if err != nil {
				t.Error("LoadContainerFp(fp, true):", err)
			}

			if err = fimg.UnloadContainer(); err != nil {
				t.Error("fimg.UnloadContainer():", err)
			}
		})
	}
}

type mockSifReadWriter struct {
	buf []byte
	pos int64
}

func (m *mockSifReadWriter) ReadAt(b []byte, off int64) (n int, err error) {
	if off >= int64(len(m.buf)) {
		return 0, io.EOF
	}

	return copy(b, m.buf[off:]), nil
}

func (m *mockSifReadWriter) Seek(offset int64, whence int) (ret int64, err error) {
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

func (m *mockSifReadWriter) Truncate(size int64) error {
	m.pos = 0
	return nil
}

func (m *mockSifReadWriter) Write(b []byte) (n int, err error) {
	if len(b) > cap(m.buf[m.pos:]) {
		buf := make([]byte, m.pos, m.pos+int64(len(b)))
		copy(buf, m.buf)
		m.buf = buf
	}

	n = copy(m.buf[m.pos:cap(m.buf)], b)

	m.pos += int64(n)

	m.buf = m.buf[:m.pos]

	return n, err
}

func TestLoadContainerFpMock(t *testing.T) {
	// This test is using mockSifReadWriter to verify that the code
	// is not making assumptions regading the behavior of the
	// ReadWriter it's getting, as mockSifReadWriter implements a
	// very dumb buffer. This specific test could be exteded to test
	// for more error conditions as it would be possible to report
	// errors from cases where it would be otherwise hard to do so
	// (e.g. Seek, ReadAt or Truncate reporting errors).

	// Load a valid SIF file to test the happy path.
	content, err := ioutil.ReadFile("testdata/testcontainer2.sif")
	if err != nil {
		t.Error(`ioutil.ReadFile("testdata/testcontainer2.sif"):`, err)
	}

	fp := &mockSifReadWriter{
		buf: content,
	}

	fimg, err := LoadContainerFp(fp, true)
	if err != nil {
		t.Error("LoadContainerFp(fp, true):", err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error("fimg.UnloadContainer():", err)
	}
}

func TestLoadContainerInvalidMagic(t *testing.T) {
	// Load a valid SIF file ...
	content, err := ioutil.ReadFile("testdata/testcontainer2.sif")
	if err != nil {
		t.Error(`ioutil.ReadFile("testdata/testcontainer2.sif"):`, err)
	}

	// ... and edit the magic to make it invalid. Instead of
	// exploring all kinds of invalid, simply mess with the last
	// byte, as this would catch off-by-one errors in the code.
	copy(content[hdrLaunchLen:hdrLaunchLen+hdrMagicLen], "SIF_MAGIX")

	fp := &mockSifReadWriter{
		buf: content,
	}

	fimg, err := LoadContainerFp(fp, true)
	if err == nil {
		// unload the container in case it's loaded, ignore
		// any errors
		_ = fimg.UnloadContainer()
		t.Errorf(`LoadContainerFp(fp, true) did not report an error for a container with invalid magic.`)
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
	if err != nil || fimg.descrArr != nil {
		t.Error(`LoadContainerReader(buf):`, err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error(`fimg.UnloadContainer():`, err)
	}

	// this buffer is big enough to include header + complete DescrArr
	r = bytes.NewReader(content[:32768])
	fimg, err = LoadContainerReader(r)
	if err != nil {
		t.Error(`LoadContainerReader(buf):`, err)
	}

	if err = fimg.UnloadContainer(); err != nil {
		t.Error(`fimg.UnloadContainer():`, err)
	}
}

func TestTrimZeroBytes(t *testing.T) {
	tt := []struct {
		name   string
		in     []byte
		expect string
	}{
		{
			name:   "no zero",
			in:     []byte("hello!"),
			expect: "hello!",
		},
		{
			name:   "c string x00",
			in:     []byte("hello!\x00"),
			expect: "hello!",
		},
		{
			name:   "c string 000",
			in:     []byte("hello!\000"),
			expect: "hello!",
		},
		{
			name:   "many zeroes x00",
			in:     []byte("hello!\x00\x00\x00\x00\x00\x00\x00"),
			expect: "hello!",
		},
		{
			name:   "many zeroes 000",
			in:     []byte("hello!\000\000\000\000\000\000\000"),
			expect: "hello!",
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			actual := trimZeroBytes(tc.in)
			if tc.expect != actual {
				t.Fatalf("Expected %q, but got %q", tc.expect, actual)
			}
		})
	}
}
