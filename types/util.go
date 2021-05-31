package types

import (
	"crypto/sha256"
)

func Hash(buf []byte) *[HashSize]byte {
	var ret [HashSize]byte
	hash := sha256.New()
	hash.Write(buf)
	copy(ret[:], hash.Sum(nil))
	return &ret
}
