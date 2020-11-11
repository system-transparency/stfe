package testdata

import (
	"testing"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
)

// NewGetLatestSignedLogRootResponse creates a new trillian STH.  Revision,
// Metadata, Proof, KeyHint, and LogRootSignature are unsset.
func NewGetLatestSignedLogRootResponse(t *testing.T, timestamp, size uint64, hash []byte) *trillian.GetLatestSignedLogRootResponse {
	t.Helper()
	return &trillian.GetLatestSignedLogRootResponse{
		SignedLogRoot: marshalSignedLogRoot(t, &types.LogRootV1{
			TreeSize:       size,
			RootHash:       hash,
			TimestampNanos: timestamp,
			Revision:       0,   // not used by stfe
			Metadata:       nil, // not used by stfe
		}),
		Proof: nil, // not used by stfe
	}
}

// TruncatedSignedLogRootResponse creates a truncated signed log root response
// that cannot be unmarshalled, i.e., SignedLogRoot.LogRoot is invalid.
func TruncatedSignedLogRootResponse(t *testing.T) *trillian.GetLatestSignedLogRootResponse {
	t.Helper()
	slrr := NewGetLatestSignedLogRootResponse(t, 0, 0, make([]byte, 32))
	slrr.SignedLogRoot.LogRoot = slrr.SignedLogRoot.LogRoot[1:]
	return slrr
}

// marshalSignedLogRoot must marshal a signed log root
func marshalSignedLogRoot(t *testing.T, lr *types.LogRootV1) *trillian.SignedLogRoot {
	t.Helper()
	rootBytes, err := lr.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal root in test: %v", err)
	}
	return &trillian.SignedLogRoot{
		KeyHint:          nil, // not used by stfe
		LogRoot:          rootBytes,
		LogRootSignature: nil, // not used by stfe
	}
}
