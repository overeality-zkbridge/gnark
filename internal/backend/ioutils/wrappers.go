package ioutils

import (
	"io"
)

type WriterCounter struct {
	W io.Writer
	N int64
}

func (w *WriterCounter) Write(p []byte) (n int, err error) {
	n, err = w.W.Write(p)
	w.N += int64(n)
	return
}

func Read(r io.Reader, size int) ([]byte, error) {
	data := make([]byte, size)
	totalRead := 0
	for {
		n, err := r.Read(data[totalRead:size])
		totalRead += n

		if totalRead == size {
			return data, nil
		}
		if err != nil {
			return data, err
		}
	}
}
