package stfe

import (
	"fmt"
	"time"

	"crypto"
	"crypto/rand"
)

// genV1Sdi issues a new SignedDebugInfoV1 StItem from a serialized leaf value
func (lp *LogParameters) genV1Sdi(serialized []byte) (*StItem, error) {
	sig, err := lp.Signer.Sign(rand.Reader, serialized, crypto.Hash(0)) // ed25519
	if err != nil {
		return nil, fmt.Errorf("ed25519 signature failed: %v", err)
	}
	lastSdiTimestamp.Set(float64(time.Now().Unix()), lp.id())
	return NewSignedDebugInfoV1(lp.LogId, []byte("reserved"), sig), nil
}

// genV1Sth issues a new SignedTreeHeadV1 StItem from a TreeHeadV1 structure
func (lp *LogParameters) genV1Sth(th *TreeHeadV1) (*StItem, error) {
	serialized, err := th.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed tls marshaling tree head: %v", err)
	}
	sig, err := lp.Signer.Sign(rand.Reader, serialized, crypto.Hash(0)) // ed25519
	if err != nil {
		return nil, fmt.Errorf("ed25519 signature failed: %v", err)
	}
	lastSthTimestamp.Set(float64(time.Now().Unix()), lp.id())
	lastSthSize.Set(float64(th.TreeSize), lp.id())
	return NewSignedTreeHeadV1(th, lp.LogId, sig), nil
}
