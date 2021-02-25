package stfe

import (
	"crypto"
	"fmt"
	"time"

	"crypto/rand"

	"github.com/system-transparency/stfe/types"
)

// LogParameters is a collection of log parameters
type LogParameters struct {
	LogId      *types.Namespace     // log identifier
	LogIdBytes []byte               // serialized log id
	TreeId     int64                // used internally by Trillian
	Prefix     string               // e.g., "test" for <base>/test
	MaxRange   int64                // max entries per get-entries request
	Submitters *types.NamespacePool // trusted submitters
	Witnesses  *types.NamespacePool // trusted witnesses
	Deadline   time.Duration        // gRPC deadline
	Interval   time.Duration        // cosigning sth frequency
	HashType   crypto.Hash          // hash function used by Trillian
	Signer     crypto.Signer        // access to Ed25519 private key
}

// NewLogParameters creates newly initialized log parameters
func NewLogParameters(signer crypto.Signer, logId *types.Namespace, treeId int64, prefix string, submitters, witnesses *types.NamespacePool, maxRange int64, interval, deadline time.Duration) (*LogParameters, error) {
	logIdBytes, err := types.Marshal(*logId)
	if err != nil {
		return nil, fmt.Errorf("Marshal failed for log identifier: %v", err)
	}
	return &LogParameters{
		LogId:      logId,
		TreeId:     treeId,
		Prefix:     prefix,
		MaxRange:   maxRange,
		Submitters: submitters,
		Witnesses:  witnesses,
		Deadline:   deadline,
		Interval:   interval,
		HashType:   crypto.SHA256,
		Signer:     signer,
		LogIdBytes: logIdBytes,
	}, nil
}

// SignTreeHeadV1 signs a TreeHeadV1 structure
func (lp *LogParameters) SignTreeHeadV1(th *types.TreeHeadV1) (*types.StItem, error) {
	serialized, err := types.Marshal(*th)
	if err != nil {
		return nil, fmt.Errorf("Marshal failed for TreeHeadV1: %v", err)
	}
	sig, err := lp.Signer.Sign(rand.Reader, serialized, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("Sign failed: %v", err)
	}
	lastSthTimestamp.Set(float64(time.Now().Unix()), string(lp.LogIdBytes))
	lastSthSize.Set(float64(th.TreeSize), string(lp.LogIdBytes))
	return &types.StItem{
		Format: types.StFormatSignedTreeHeadV1,
		SignedTreeHeadV1: &types.SignedTreeHeadV1{
			TreeHead: *th,
			Signature: types.SignatureV1{
				Namespace: *lp.LogId,
				Signature: sig,
			},
		},
	}, nil
}
