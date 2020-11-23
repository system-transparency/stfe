package stfe

import (
	"fmt"
	"testing"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/system-transparency/stfe/testdata"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCheckQueueLeaf(t *testing.T) {
	for _, table := range []struct {
		description string
		rsp         *trillian.QueueLeafResponse
		err         error
		wantErr     bool
	}{
		{
			description: "trillian error",
			err:         fmt.Errorf("backend error"),
			wantErr:     true,
		},
		{
			description: "empty trillian response",
			wantErr:     true,
		},
		{
			description: "partial trillian response: empty QueuedLeaf field",
			rsp:         &trillian.QueueLeafResponse{},
			wantErr:     true,
		},
		{
			description: "ok: duplicate leaf",
			rsp:         makeTrillianQueueLeafResponse(t, testPackage, testdata.FirstPemChain, testdata.FirstPemChainKey, true),
		},
		{
			description: "ok: new leaf",
			rsp:         makeTrillianQueueLeafResponse(t, testPackage, testdata.FirstPemChain, testdata.FirstPemChainKey, false),
		},
	} {
		if err := checkQueueLeaf(table.rsp, table.err); (err != nil) != table.wantErr {
			t.Errorf("got error %v, but wanted error %v in test %q", err, table.wantErr, table.description)
		}
	}
}

func TestCheckGetLeavesByRange(t *testing.T) {
	// rsp without leaves
	noLeaves := makeTrillianGetLeavesByRangeResponse(t, 0, 1, testPackage, testdata.FirstPemChain, testdata.FirstPemChainKey, true)
	noLeaves.Leaves = nil

	// rsp without signed log root
	noSlr := makeTrillianGetLeavesByRangeResponse(t, 0, 1, testPackage, testdata.FirstPemChain, testdata.FirstPemChainKey, true)
	noSlr.SignedLogRoot = nil

	// rsp without log root
	noLr := makeTrillianGetLeavesByRangeResponse(t, 0, 1, testPackage, testdata.FirstPemChain, testdata.FirstPemChainKey, true)
	noLr.SignedLogRoot.LogRoot = nil

	// rsp with root that cannot be unmarshalled
	tr := makeTrillianGetLeavesByRangeResponse(t, 0, 1, testPackage, testdata.FirstPemChain, testdata.FirstPemChainKey, true)
	tr.SignedLogRoot.LogRoot = tr.SignedLogRoot.LogRoot[1:]

	// rsp with fixed tree size
	fixedSize := makeTrillianGetLeavesByRangeResponse(t, int64(testTreeSize)-1, int64(testTreeSize)-1, testPackage, testdata.FirstPemChain, testdata.FirstPemChainKey, true)
	fixedSize.SignedLogRoot = makeLatestSignedLogRootResponse(t, 0, testTreeSize, testNodeHash).SignedLogRoot

	for _, table := range []struct {
		description string
		req         *GetEntriesRequest
		rsp         *trillian.GetLeavesByRangeResponse
		err         error
		wantErr     bool
	}{
		{
			description: "trillian error",
			err:         fmt.Errorf("backend error"),
			wantErr:     true,
		},
		{
			description: "empty trillian response",
			wantErr:     true,
		},
		{
			description: "partial trillian response: no leaves",
			rsp:         noLeaves,
			wantErr:     true,
		},
		{
			description: "partial trillian response: no signed log root",
			rsp:         noSlr,
			wantErr:     true,
		},
		{
			description: "partial trillian response: no log root",
			rsp:         noLr,
			wantErr:     true,
		},
		{
			description: "bad response: too many leaves",
			req:         &GetEntriesRequest{Start: 0, End: 1},
			rsp:         makeTrillianGetLeavesByRangeResponse(t, 0, 2, testPackage, testdata.FirstPemChain, testdata.FirstPemChainKey, true),
			wantErr:     true,
		},
		{
			description: "bad response: too many leaves",
			req:         &GetEntriesRequest{Start: 0, End: 1},
			rsp:         tr,
			wantErr:     true,
		},
		{
			description: "bad response: start is not a valid index",
			req:         &GetEntriesRequest{Start: int64(testTreeSize), End: int64(testTreeSize)},
			rsp:         fixedSize,
			wantErr:     true,
		},
		{
			description: "ok response: interval refers to the latest leaf",
			req:         &GetEntriesRequest{Start: int64(testTreeSize) - 1, End: int64(testTreeSize) - 1},
			rsp:         fixedSize,
		},
		{
			description: "bad response: invalid leaf indices",
			req:         &GetEntriesRequest{Start: 10, End: 11},
			rsp:         makeTrillianGetLeavesByRangeResponse(t, 11, 12, testPackage, testdata.FirstPemChain, testdata.FirstPemChainKey, true),
			wantErr:     true,
		},
		{
			description: "ok response: a bunch of leaves",
			req:         &GetEntriesRequest{Start: 10, End: 20},
			rsp:         makeTrillianGetLeavesByRangeResponse(t, 10, 20, testPackage, testdata.FirstPemChain, testdata.FirstPemChainKey, true),
		},
	} {
		if _, err := checkGetLeavesByRange(table.req, table.rsp, table.err); (err != nil) != table.wantErr {
			t.Errorf("got error %v, but wanted error %v in test %q", err, table.wantErr, table.description)
		}
	}
}

// TODO: TestCheckGetInclusionProofByHash
func TestCheckGetInclusionProofByHash(t *testing.T) {
}

// TODO: TestGetConsistencyProof
func TestCheckGetConsistencyProof(t *testing.T) {
}

func TestCheckGetLatestSignedLogRoot(t *testing.T) {
	// response with no log root
	noLr := makeLatestSignedLogRootResponse(t, 0, 0, testNodeHash)
	noLr.SignedLogRoot.LogRoot = nil

	// response with truncated log root
	tr := makeLatestSignedLogRootResponse(t, 0, 0, testNodeHash)
	tr.SignedLogRoot.LogRoot = tr.SignedLogRoot.LogRoot[1:]

	lp := makeTestLogParameters(t, nil)
	for _, table := range []struct {
		description string
		rsp         *trillian.GetLatestSignedLogRootResponse
		err         error
		wantErr     bool
	}{
		{
			description: "bad trillian response: error",
			err:         fmt.Errorf("backend failure"),
			wantErr:     true,
		},
		{
			description: "bad trillian response: empty",
			wantErr:     true,
		},
		{
			description: "bad trillian response: no signed log root",
			rsp:         &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: nil},
			wantErr:     true,
		},
		{
			description: "bad trillian response: no log root",
			rsp:         noLr,
			wantErr:     true,
		},
		{
			description: "bad trillian response: truncated log root",
			rsp:         tr,
			wantErr:     true,
		},
		{
			description: "bad trillian response: invalid root hash size",
			rsp:         makeLatestSignedLogRootResponse(t, 0, 0, make([]byte, 31)),
			wantErr:     true,
		},
		{
			description: "ok response",
			rsp:         makeLatestSignedLogRootResponse(t, 0, 0, testNodeHash),
		},
	} {
		var lr types.LogRootV1
		if err := checkGetLatestSignedLogRoot(lp, table.rsp, table.err, &lr); (err != nil) != table.wantErr {
			t.Errorf("got error %v, but wanted error %v in test %q", err, table.wantErr, table.description)
		}
	}
}

// makeTrillianQueueLeafResponse creates a valid trillian QueueLeafResponse
// for a package `name` where the checksum is all zeros (32 bytes).  The pemKey
// is a PEM-encoded ed25519 signing key, and pemChain its certificate chain.
//
// Note: MerkleLeafHash and LeafIdentityHash are unset (not used by stfe).
func makeTrillianQueueLeafResponse(t *testing.T, name, pemChain, pemKey []byte, dupCode bool) *trillian.QueueLeafResponse {
	t.Helper()
	leaf, appendix := makeTestLeaf(t, name, pemChain, pemKey)
	s := status.New(codes.OK, "ok").Proto()
	if dupCode {
		s = status.New(codes.AlreadyExists, "duplicate").Proto()
	}
	return &trillian.QueueLeafResponse{
		QueuedLeaf: &trillian.QueuedLogLeaf{
			Leaf: &trillian.LogLeaf{
				MerkleLeafHash:   nil, // not used by stfe
				LeafValue:        leaf,
				ExtraData:        appendix,
				LeafIndex:        0,   // not applicable (log is not pre-ordered)
				LeafIdentityHash: nil, // not used by stfe
			},
			Status: s,
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
	leaves := make([]*trillian.LogLeaf, 0, end-start+1)
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
		SignedLogRoot: makeLatestSignedLogRootResponse(t, 0, uint64(end)+1, make([]byte, 32)).SignedLogRoot,
	}
}

// makeTrillianLogRoot: docdoc
func makeTrillianLogRoot(t *testing.T, timestamp, size uint64, hash []byte) *types.LogRootV1 {
	t.Helper()
	return &types.LogRootV1{
		TreeSize:       size,
		RootHash:       hash,
		TimestampNanos: timestamp,
		Revision:       0,   // not used by stfe
		Metadata:       nil, // not used by stfe
	}
}

// makeLatestSignedLogRootResponse creates a new trillian STH.  Revision,
// Metadata, Proof, KeyHint, and LogRootSignature are unsset.
func makeLatestSignedLogRootResponse(t *testing.T, timestamp, size uint64, hash []byte) *trillian.GetLatestSignedLogRootResponse {
	t.Helper()
	rootBytes, err := makeTrillianLogRoot(t, timestamp, size, hash).MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal root in test: %v", err)
	}
	return &trillian.GetLatestSignedLogRootResponse{
		SignedLogRoot: &trillian.SignedLogRoot{
			KeyHint:          nil, // not used by stfe
			LogRoot:          rootBytes,
			LogRootSignature: nil, // not used by stfe
		},
		Proof: nil, // not used by stfe
	}
}
