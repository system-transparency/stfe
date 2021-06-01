package types

import (
	"crypto/sha256"
)

const (
	LeafHashPrefix = 0x00
)

func Hash(buf []byte) *[HashSize]byte {
	var ret [HashSize]byte
	hash := sha256.New()
	hash.Write(buf)
	copy(ret[:], hash.Sum(nil))
	return &ret
}

func HashLeaf(buf []byte) *[HashSize]byte {
	return Hash(append([]byte{LeafHashPrefix}, buf...))
}
