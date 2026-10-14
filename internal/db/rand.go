package db

import (
	"crypto/rand"
	"encoding/binary"
)

func randUint() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}
