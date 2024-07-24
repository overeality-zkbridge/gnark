package cs

import (
	"encoding/binary"
	"fmt"
	"github.com/consensys/gnark/internal/backend/ioutils"
	"io"
	"time"
)

func uint64ToByte(x uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], x)
	return b[:]
}

func encodeU32Array(data []uint32) []byte {
	res := make([]byte, len(data)*4)
	for i, v := range data {
		binary.LittleEndian.PutUint32(res[i*4:i*4+4], v)
	}
	return res
}

func decodeU32Array(bytes []byte) []uint32 {
	res := make([]uint32, len(bytes)/4)
	for i := 0; i < len(res); i++ {
		res[i] = binary.LittleEndian.Uint32(bytes[i*4 : i*4+4])
	}
	return res
}

func encodeCallDataToWriter(w io.Writer, callData []uint32) error {
	start := time.Now()
	defer func() {
		fmt.Printf("Encoding CallData done, took %0.2fs\n", time.Since(start).Seconds())
	}()
	data := encodeU32Array(callData)
	_, err := w.Write(uint64ToByte(uint64(len(data))))
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func decodeCallDataFromReader(r io.Reader) ([]uint32, error) {
	t0 := time.Now()
	defer func() {
		fmt.Printf("Decoding CallData took: %0.2fs\n", time.Now().Sub(t0).Seconds())
	}()

	var sizeBytes [8]byte
	_, err := r.Read(sizeBytes[:])
	if err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint64(sizeBytes[:])

	bytes, err := ioutils.Read(r, int(size))
	if err != nil {
		return nil, err
	}
	result := decodeU32Array(bytes)

	return result, nil
}
