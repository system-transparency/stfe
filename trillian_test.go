package stfe

import (
	"fmt"
	"testing"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/system-transparency/stfe/server/testdata"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TODO: TestCheckQueueLeaf
func TestCheckQueueLeaf(t *testing.T) {
}

// TODO: TestCheckGetLeavesByRange
func TestCheckGetLeavesByRange(t *testing.T) {
}

// TODO: TestCheckGetInclusionProofByHash
func TestCheckGetInclusionProofByHash(t *testing.T) {
}

// TODO: TestGetConsistencyProof
func TestCheckGetConsistencyProof(t *testing.T) {
}

// TODO: TestCheckGetLatestSignedLogRoot
func TestCheckGetLatestSignedLogRoot(t *testing.T) {
}

// makeTrillianQueueLeafResponse creates a valid trillian QueueLeafResponse
// for a package `name` where the checksum is all zeros (32 bytes).  The pemKey
// is a PEM-encoded ed25519 signing key, and pemChain its certificate chain.
//
// Note: MerkleLeafHash and LeafIdentityHash are unset (not used by stfe).
func makeTrillianQueueLeafResponse(t *testing.T, name, pemChain, pemKey []byte) *trillian.QueueLeafResponse {
	t.Helper()
	leaf, appendix := makeTestLeaf(t, name, pemChain, pemKey)
	return &trillian.QueueLeafResponse{
		QueuedLeaf: &trillian.QueuedLogLeaf{
			Leaf: &trillian.LogLeaf{
				MerkleLeafHash:   nil, // not used by stfe
				LeafValue:        leaf,
				ExtraData:        appendix,
				LeafIndex:        0,   // not applicable (log is not pre-ordered)
				LeafIdentityHash: nil, // not used by stfe
			},
			Status: status.New(codes.OK, "ok").Proto(),
		},
	}
}

// makeTrillianGetInclusionProofByHashResponse populates a get-proof-by-hash
// response.
//
// Note: SignedLogRoot is unset (not used by stfe).
func makeTrillianGetInclusionProofByHashResponse(t *testing.T, index int64, path [][]byte) *trillian.GetInclusionProofByHashResponse {
	t.Helper()
	return &trillian.GetInclusionProofByHashResponse{
		Proof: []*trillian.Proof{
			&trillian.Proof{
				LeafIndex: index,
				Hashes:    path,
			},
		},
		SignedLogRoot: nil,
	}
}

// makeTrillianGetConsistencyProofResponse populates a get-consistency response.
//
// Note: LeafIndex is not applicable for a consistency proof (0), and
// SignedLogRoot is unset (not used by stfe).
func makeTrillianGetConsistencyProofResponse(t *testing.T, path [][]byte) *trillian.GetConsistencyProofResponse {
	t.Helper()
	return &trillian.GetConsistencyProofResponse{
		Proof: &trillian.Proof{
			LeafIndex: 0,
			Hashes:    path,
		},
		SignedLogRoot: nil,
	}
}

// makeTrillianGetLeavesByRangeResponse creates a range of leaves [start,end]
// such that the package is `name`_<index> and the checksum is all zeros (32
// bytes).  The pemKey is a PEM-encoded ed25519 signing key, and pemChain its
// certificate chain.  Set `valid` to false to make an invalid Appendix.
//
// Note: MerkleLeafHash and LeafIdentityHash are unset (not used by stfe).
func makeTrillianGetLeavesByRangeResponse(t *testing.T, start, end int64, name, pemChain, pemKey []byte, valid bool) *trillian.GetLeavesByRangeResponse {
	t.Helper()
	leaves := make([]*trillian.LogLeaf, 0, start-end+1)
	for i, n := start, end+1; i < n; i++ {
		leaf, appendix := makeTestLeaf(t, append(name, []byte(fmt.Sprintf("_%d", i))...), pemChain, pemKey)
		if !valid {
			appendix = []byte{0, 1, 2, 3}
		}
		leaves = append(leaves, &trillian.LogLeaf{
			MerkleLeafHash:   nil,
			LeafValue:        leaf,
			ExtraData:        appendix,
			LeafIndex:        i,
			LeafIdentityHash: nil,
		})
	}
	return &trillian.GetLeavesByRangeResponse{
		Leaves:        leaves,
		SignedLogRoot: testdata.NewGetLatestSignedLogRootResponse(t, 0, uint64(end)+1, make([]byte, 32)).SignedLogRoot,
	}
}

func makeTrillianLogRoot(t *testing.T, timestamp, size uint64, hash []byte) *types.LogRootV1 {
	return &types.LogRootV1{
		TreeSize:       size,
		RootHash:       hash,
		TimestampNanos: timestamp,
		Revision:       0,   // not used by stfe
		Metadata:       nil, // not used by stfe
	}
}
