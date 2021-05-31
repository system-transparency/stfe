package stfe

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/system-transparency/stfe/types"
)

// LogParameters is a collection of log parameters
type LogParameters struct {
	LogId    string        // serialized log id (hex)
	TreeId   int64         // used internally by Trillian
	Prefix   string        // e.g., "test" for <base>/test
	MaxRange int64         // max entries per get-entries request
	Deadline time.Duration // gRPC deadline
	Interval time.Duration // cosigning sth frequency
	HashType crypto.Hash   // hash function used by Trillian
	Signer   crypto.Signer // access to Ed25519 private key

	// Witnesses map trusted witness identifiers to public verification keys
	Witnesses map[[types.HashSize]byte][types.VerificationKeySize]byte
}

// Sign signs a tree head
func (lp *LogParameters) Sign(th *types.TreeHead) (*types.SignedTreeHead, error) {
	sig, err := lp.Signer.Sign(nil, th.Marshal(), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("Sign failed: %v", err)
	}
	lastSthTimestamp.Set(float64(time.Now().Unix()), lp.LogId)
	lastSthSize.Set(float64(th.TreeSize), lp.LogId)

	sigident := types.SigIdent{
		KeyHash:   types.Hash(lp.Signer.Public().(ed25519.PublicKey)[:]),
		Signature: &[types.SignatureSize]byte{},
	}
	copy(sigident.Signature[:], sig)
	return &types.SignedTreeHead{
		TreeHead: *th,
		SigIdent: []*types.SigIdent{
			&sigident,
		},
	}, nil
}
