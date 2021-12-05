// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestBuffer_ReadAt(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		pos     int64
		p       []byte
		off     int64
		wantErr error
		want    []byte
	}{
		{
			name:    "OffsetNegative",
			buf:     []byte{0x01, 0x02},
			off:     -1,
			wantErr: errNegativeOffset,
		},
		{
			name:    "OffsetEOF",
			buf:     []byte{0x01, 0x02},
			off:     2,
			wantErr: io.EOF,
		},
		{
			name: "ShortRead",
			buf:  []byte{0x01, 0x02},
			p:    make([]byte, 1),
			want: []byte{0x01},
		},
		{
			name: "FullRead",
			buf:  []byte{0x01, 0x02},
			p:    make([]byte, 2),
			want: []byte{0x01, 0x02},
		},
		{
			name:    "EOFRead",
			buf:     []byte{0x01, 0x02},
			p:       make([]byte, 3),
			wantErr: io.EOF,
			want:    []byte{0x01, 0x02},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Buffer{
				buf: tt.buf,
				pos: tt.pos,
			}

			n, err := b.ReadAt(tt.p, tt.off)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if got, want := n, len(tt.want); got != want {
				t.Errorf("got n %v, want %v", got, want)
			}

			if got, want := tt.p[:n], tt.want; !bytes.Equal(got, want) {
				t.Errorf("got bytes %v, want %v", got, want)
			}
		})
	}
}

func TestBuffer_Write(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		pos     int64
		p       []byte
		wantErr error
		wantN   int
		wantBuf []byte
		wantPos int64
	}{
		{
			name:    "NegativePosition",
			pos:     -1,
			wantErr: errNegativePosition,
			wantPos: -1,
		},
		{
			name:    "Overwrite",
			buf:     []byte{0x01, 0x02},
			pos:     0,
			p:       []byte{0x03, 0x04},
			wantN:   2,
			wantBuf: []byte{0x03, 0x04},
			wantPos: 2,
		},
		{
			name:    "OverwriteAppend",
			buf:     []byte{0x01, 0x02},
			pos:     1,
			p:       []byte{0x03, 0x04},
			wantN:   2,
			wantBuf: []byte{0x01, 0x03, 0x04},
			wantPos: 3,
		},
		{
			name:    "Append",
			buf:     []byte{0x01, 0x02},
			pos:     2,
			p:       []byte{0x03, 0x04},
			wantN:   2,
			wantBuf: []byte{0x01, 0x02, 0x03, 0x04},
			wantPos: 4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Buffer{
				buf: tt.buf,
				pos: tt.pos,
			}

			n, err := b.Write(tt.p)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if got, want := n, tt.wantN; got != want {
				t.Errorf("got n %v, want %v", got, want)
			}

			if got, want := b.buf, tt.wantBuf; !bytes.Equal(got, want) {
				t.Errorf("got buffer %v, want %v", got, want)
			}

			if got, want := b.pos, tt.wantPos; got != want {
				t.Errorf("got position %v, want %v", got, want)
			}
		})
	}
}

func TestBuffer_Seek(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		pos     int64
		offset  int64
		whence  int
		wantErr error
		wantPos int64
	}{
		{
			name:    "InvalidWhence",
			buf:     []byte{0x01, 0x02},
			offset:  0,
			whence:  -1,
			wantErr: errInvalidWhence,
		},
		{
			name:    "StartError",
			buf:     []byte{0x01, 0x02},
			pos:     1,
			offset:  -1,
			whence:  io.SeekStart,
			wantErr: errNegativePosition,
		},
		{
			name:    "StartZero",
			buf:     []byte{0x01, 0x02},
			pos:     1,
			offset:  0,
			whence:  io.SeekStart,
			wantPos: 0,
		},
		{
			name:    "StartTwo",
			buf:     []byte{0x01, 0x02},
			pos:     1,
			offset:  2,
			whence:  io.SeekStart,
			wantPos: 2,
		},
		{
			name:    "CurrentError",
			buf:     []byte{0x01, 0x02},
			pos:     1,
			offset:  -2,
			whence:  io.SeekCurrent,
			wantErr: errNegativePosition,
		},
		{
			name:    "CurrentNegative",
			buf:     []byte{0x01, 0x02},
			pos:     1,
			offset:  -1,
			whence:  io.SeekCurrent,
			wantPos: 0,
		},
		{
			name:    "CurrentPositive",
			buf:     []byte{0x01, 0x02},
			pos:     1,
			offset:  1,
			whence:  io.SeekCurrent,
			wantPos: 2,
		},
		{
			name:    "EndError",
			buf:     []byte{0x01, 0x02},
			pos:     1,
			offset:  -3,
			whence:  io.SeekEnd,
			wantErr: errNegativePosition,
		},
		{
			name:    "EndZero",
			buf:     []byte{0x01, 0x02},
			pos:     1,
			offset:  0,
			whence:  io.SeekEnd,
			wantPos: 2,
		},
		{
			name:    "EndTwo",
			buf:     []byte{0x01, 0x02},
			pos:     1,
			offset:  -2,
			whence:  io.SeekEnd,
			wantPos: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Buffer{
				buf: tt.buf,
				pos: tt.pos,
			}

			pos, err := b.Seek(tt.offset, tt.whence)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if got, want := pos, tt.wantPos; got != want {
				t.Fatalf("got position %v, want %v", got, want)
			}
		})
	}
}

func TestBuffer_Truncate(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		n       int64
		wantErr error
		want    []byte
	}{
		{
			name:    "RangeNegative",
			buf:     []byte{0x01, 0x02},
			n:       -1,
			wantErr: errTruncateRange,
			want:    []byte{0x01, 0x02},
		},
		{
			name:    "RangePositive",
			buf:     []byte{0x01, 0x02},
			n:       3,
			wantErr: errTruncateRange,
			want:    []byte{0x01, 0x02},
		},
		{
			name: "Zero",
			buf:  []byte{0x01, 0x02},
			n:    0,
			want: []byte{},
		},
		{
			name: "One",
			buf:  []byte{0x01, 0x02},
			n:    1,
			want: []byte{0x01},
		},
		{
			name: "Two",
			buf:  []byte{0x01, 0x02},
			n:    2,
			want: []byte{0x01, 0x02},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Buffer{
				buf: tt.buf,
			}

			err := b.Truncate(tt.n)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if got, want := b.buf, tt.want; !bytes.Equal(got, want) {
				t.Errorf("got buffer %v, want %v", got, want)
			}
		})
	}
}

func TestBuffer_Bytes(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want []byte
	}{
		{
			name: "Nil",
			buf:  nil,
			want: nil,
		},
		{
			name: "Empty",
			buf:  []byte{},
			want: []byte{},
		},
		{
			name: "One",
			buf:  []byte{0x01},
			want: []byte{0x01},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Buffer{
				buf: tt.buf,
			}

			if got, want := b.Bytes(), tt.want; !bytes.Equal(got, want) {
				t.Errorf("got bytes %v, want %v", got, want)
			}
		})
	}
}

func TestBuffer_Len(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want int64
	}{
		{
			name: "Nil",
			buf:  nil,
			want: 0,
		},
		{
			name: "Empty",
			buf:  []byte{},
			want: 0,
		},
		{
			name: "One",
			buf:  []byte{0x01},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Buffer{
				buf: tt.buf,
			}

			if got, want := b.Len(), tt.want; got != want {
				t.Errorf("got length %v, want %v", got, want)
			}
		})
	}
}
