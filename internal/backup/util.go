package backup

import (
	"bytes"
	"io"
)

// countingBuffer is a bytes.Buffer that also exposes the byte count.
type countingBuffer struct {
	*bytes.Buffer
}

func newCountingBuffer() *countingBuffer { return &countingBuffer{Buffer: &bytes.Buffer{}} }

// seekingReader wraps a byte slice as an io.ReadSeeker (some destinations
// re-read on retry).
type seekingReader struct {
	r *bytes.Reader
}

func newSeekingReader(b []byte) *seekingReader { return &seekingReader{r: bytes.NewReader(b)} }

func (s *seekingReader) Read(p []byte) (int, error)         { return s.r.Read(p) }
func (s *seekingReader) Seek(o int64, w int) (int64, error) { return s.r.Seek(o, w) }
func (s *seekingReader) Len() int                           { return s.r.Len() }

var _ io.ReadSeeker = (*seekingReader)(nil)
