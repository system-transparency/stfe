package stfe

import (
	"fmt"
	"testing"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/system-transparency/stfe/x509util/testdata"

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
			description: "bad response: trillian error",
			err:         fmt.Errorf("backend error"),
			wantErr:     true,
		},
		{
			description: "bad response: empty",
			wantErr:     true,
		},
		{
			description: "bad response: no queued leaf",
			rsp:         &trillian.QueueLeafResponse{},
			wantErr:     true,
		},
		{
			description: "ok response: duplicate leaf",
			rsp:         makeTrillianQueueLeafResponse(t, testPackage, testdata.IntermediateChain, testdata.EndEntityPrivateKey, true),
		},
		{
			description: "ok response: new leaf",
			rsp:         makeTrillianQueueLeafResponse(t, testPackage, testdata.IntermediateChain, testdata.EndEntityPrivateKey, false),
		},
	} {
		if err := checkQueueLeaf(table.rsp, table.err); (err != nil) != table.wantErr {
			t.Errorf("got error %v, but wanted error %v in test %q", err, table.wantErr, table.description)
		}
	}
}

func TestCheckGetLeavesByRange(t *testing.T) {
	for _, table := range []struct {
		description string
		req         *GetEntriesRequest
		rsp         *trillian.GetLeavesByRangeResponse
		err         error
		wantErr     bool
	}{
		{
			description: "bad response: trillian error",
			req:         &GetEntriesRequest{Start: 0, End: 1},
			err:         fmt.Errorf("backend error"),
			wantErr:     true,
		},
		{
			description: "bad response: empty",
			req:         &GetEntriesRequest{Start: 0, End: 1},
			wantErr:     true,
		},
		{
			description: "bad response: no leaves",
			req:         &GetEntriesRequest{Start: 0, End: 1},
			rsp: func(rsp *trillian.GetLeavesByRangeResponse) *trillian.GetLeavesByRangeResponse {
				rsp.Leaves = nil
				return rsp
			}(makeTrillianGetLeavesByRangeResponse(t, 0, 1, testPackage, testdata.RootChain, testdata.EndEntityPrivateKey, true)),
			wantErr: true,
		},
		{
			description: "bad response: no signed log root",
			req:         &GetEntriesRequest{Start: 0, End: 1},
			rsp: func(rsp *trillian.GetLeavesByRangeResponse) *trillian.GetLeavesByRangeResponse {
				rsp.SignedLogRoot = nil
				return rsp
			}(makeTrillianGetLeavesByRangeResponse(t, 0, 1, testPackage, testdata.RootChain, testdata.EndEntityPrivateKey, true)),
			wantErr: true,
		},
		{
			description: "bad response: no log root",
			req:         &GetEntriesRequest{Start: 0, End: 1},
			rsp: func(rsp *trillian.GetLeavesByRangeResponse) *trillian.GetLeavesByRangeResponse {
				rsp.SignedLogRoot.LogRoot = nil
				return rsp
			}(makeTrillianGetLeavesByRangeResponse(t, 0, 1, testPackage, testdata.RootChain, testdata.EndEntityPrivateKey, true)),
			wantErr: true,
		},
		{
			description: "bad response: truncated root",
			req:         &GetEntriesRequest{Start: 0, End: 1},
			rsp: func(rsp *trillian.GetLeavesByRangeResponse) *trillian.GetLeavesByRangeResponse {
				rsp.SignedLogRoot.LogRoot = rsp.SignedLogRoot.LogRoot[1:]
				return rsp
			}(makeTrillianGetLeavesByRangeResponse(t, 0, 1, testPackage, testdata.RootChain, testdata.EndEntityPrivateKey, true)),
			wantErr: true,
		},
		{
			description: "bad response: too many leaves",
			req:         &GetEntriesRequest{Start: 0, End: 1},
			rsp:         makeTrillianGetLeavesByRangeResponse(t, 0, 2, testPackage, testdata.RootChain, testdata.EndEntityPrivateKey, true),
			wantErr:     true,
		},
		{
			description: "bad response: start is not a valid index",
			req:         &GetEntriesRequest{Start: int64(testTreeSize), End: int64(testTreeSize)},
			rsp: func(rsp *trillian.GetLeavesByRangeResponse) *trillian.GetLeavesByRangeResponse {
				rsp.SignedLogRoot = makeLatestSignedLogRootResponse(t, 0, testTreeSize, testNodeHash).SignedLogRoot
				return rsp
			}(makeTrillianGetLeavesByRangeResponse(t, int64(testTreeSize)-1, int64(testTreeSize)-1, testPackage, testdata.RootChain, testdata.EndEntityPrivateKey, true)),
			wantErr: true,
		},
		{
			description: "bad response: invalid leaf indices",
			req:         &GetEntriesRequest{Start: 10, End: 11},
			rsp:         makeTrillianGetLeavesByRangeResponse(t, 11, 12, testPackage, testdata.RootChain, testdata.EndEntityPrivateKey, true),
			wantErr:     true,
		},
		{
			description: "ok response: interval refers to the latest leaf",
			req:         &GetEntriesRequest{Start: int64(testTreeSize) - 1, End: int64(testTreeSize) - 1},
			rsp: func(rsp *trillian.GetLeavesByRangeResponse) *trillian.GetLeavesByRangeResponse {
				rsp.SignedLogRoot = makeLatestSignedLogRootResponse(t, 0, testTreeSize, testNodeHash).SignedLogRoot
				return rsp
			}(makeTrillianGetLeavesByRangeResponse(t, int64(testTreeSize)-1, int64(testTreeSize)-1, testPackage, testdata.RootChain, testdata.EndEntityPrivateKey, true)),
		},
		{
			description: "ok response: a bunch of leaves",
			req:         &GetEntriesRequest{Start: 10, End: 20},
			rsp:         makeTrillianGetLeavesByRangeResponse(t, 10, 20, testPackage, testdata.RootChain, testdata.EndEntityPrivateKey, true),
		},
	} {
		if _, err := checkGetLeavesByRange(table.req, table.rsp, table.err); (err != nil) != table.wantErr {
			t.Errorf("got error %v, but wanted error %v in test %q", err, table.wantErr, table.description)
		}
	}
}

func TestCheckGetInclusionProofByHash(t *testing.T) {
	lp := makeTestLogParameters(t, nil)
	for _, table := range []struct {
		description string
		rsp         *trillian.GetInclusionProofByHashResponse
		err         error
		wantErr     bool
	}{
		{
			description: "bad response: trillian error",
			err:         fmt.Errorf("backend failure"),
			wantErr:     true,
		},
		{
			description: "bad response: empty",
			wantErr:     true,
		},
		{
			description: "bad response: no proofs",
			rsp:         &trillian.GetInclusionProofByHashResponse{},
			wantErr:     true,
		},
		{
			description: "bad response: no proof",
			rsp: func(rsp *trillian.GetInclusionProofByHashResponse) *trillian.GetInclusionProofByHashResponse {
				rsp.Proof[0] = nil
				return rsp
			}(makeTrillianGetInclusionProofByHashResponse(t, int64(testIndex), testProof)),
			wantErr: true,
		},
		{
			description: "bad response: proof with invalid node hash",
			rsp:         makeTrillianGetInclusionProofByHashResponse(t, int64(testIndex), [][]byte{make([]byte, testHashLen-1)}),
			wantErr:     true,
		},
		{
			description: "ok response",
			rsp:         makeTrillianGetInclusionProofByHashResponse(t, int64(testIndex), testProof),
		},
	} {
		if err := checkGetInclusionProofByHash(lp, table.rsp, table.err); (err != nil) != table.wantErr {
			t.Errorf("got error %v, but wanted error %v in test %q", err, table.wantErr, table.description)
		}
	}
}

func TestCheckGetConsistencyProof(t *testing.T) {
	lp := makeTestLogParameters(t, nil)
	for _, table := range []struct {
		description string
		rsp         *trillian.GetConsistencyProofResponse
		err         error
		wantErr     bool
	}{
		{
			description: "bad response: trillian error",
			err:         fmt.Errorf("backend failure"),
			wantErr:     true,
		},
		{
			description: "bad response: empty",
			wantErr:     true,
		},
		{
			description: "bad response: no proof",
			rsp:         &trillian.GetConsistencyProofResponse{},
			wantErr:     true,
		},
		{
			description: "bad response: proof with invalid node hash",
			rsp:         makeTrillianGetConsistencyProofResponse(t, [][]byte{make([]byte, testHashLen-1)}),
			wantErr:     true,
		},
		{
			description: "ok response",
			rsp:         makeTrillianGetConsistencyProofResponse(t, testProof),
		},
	} {
		if err := checkGetConsistencyProof(lp, table.rsp, table.err); (err != nil) != table.wantErr {
			t.Errorf("got error %v, but wanted error %v in test %q", err, table.wantErr, table.description)
		}
	}
}

func TestCheckGetLatestSignedLogRoot(t *testing.T) {
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
			rsp: func(rsp *trillian.GetLatestSignedLogRootResponse) *trillian.GetLatestSignedLogRootResponse {
				rsp.SignedLogRoot.LogRoot = nil
				return rsp
			}(makeLatestSignedLogRootResponse(t, 0, 0, testNodeHash)),
			wantErr: true,
		},
		{
			description: "bad trillian response: truncated log root",
			rsp: func(rsp *trillian.GetLatestSignedLogRootResponse) *trillian.GetLatestSignedLogRootResponse {
				rsp.SignedLogRoot.LogRoot = rsp.SignedLogRoot.LogRoot[1:]
				return rsp
			}(makeLatestSignedLogRootResponse(t, 0, 0, testNodeHash)),
			wantErr: true,
		},
		{
			description: "bad trillian response: invalid root hash size",
			rsp:         makeLatestSignedLogRootResponse(t, 0, 0, make([]byte, testHashLen-1)),
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
