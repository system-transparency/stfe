package stfe

import (
	"fmt"
	"testing"

	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"github.com/system-transparency/stfe/testdata"
	"github.com/system-transparency/stfe/types"
)

func TestCheckQueueLeaf(t *testing.T) {
	for _, table := range []struct {
		description string
		rsp         *trillian.QueueLeafResponse
		err         error
		wantErr     bool
	}{
		{
			description: "invalid: no Trillian response: error",
			err:         fmt.Errorf("backend error"),
			wantErr:     true,
		},
		{
			description: "invalid: no Trillian response: nil",
			wantErr:     true,
		},
		{
			description: "invalid: no Trillian response: empty",
			rsp:         &trillian.QueueLeafResponse{},
			wantErr:     true,
		},
		{
			description: "valid: gRPC status: duplicate",
			rsp:         testdata.DefaultTQlr(t, true),
		},
		{
			description: "valid: gRPC status: ok",
			rsp:         testdata.DefaultTQlr(t, false),
		},
	} {
		err := checkQueueLeaf(table.rsp, table.err)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q", got, want, table.description)
		}
	}
}

func TestCheckGetLeavesByRange(t *testing.T) {
	for _, table := range []struct {
		description string
		req         *types.GetEntriesV1
		rsp         *trillian.GetLeavesByRangeResponse
		err         error
		wantErr     bool
	}{
		{
			description: "invalid: no Trillian response: error",
			req:         &types.GetEntriesV1{Start: 0, End: 1},
			err:         fmt.Errorf("backend error"),
			wantErr:     true,
		},
		{
			description: "invalid: no Trillian response: nil",
			req:         &types.GetEntriesV1{Start: 0, End: 1},
			wantErr:     true,
		},
		{
			description: "invalid: bad Trillian response: no leaves",
			req:         &types.GetEntriesV1{Start: 0, End: 1},
			rsp: func(rsp *trillian.GetLeavesByRangeResponse) *trillian.GetLeavesByRangeResponse {
				rsp.Leaves = nil
				return rsp
			}(testdata.DefaultTGlbrr(t, 0, 1)),
			wantErr: true,
		},
		{
			description: "invalid: bad Trillian response: no signed log root",
			req:         &types.GetEntriesV1{Start: 0, End: 1},
			rsp: func(rsp *trillian.GetLeavesByRangeResponse) *trillian.GetLeavesByRangeResponse {
				rsp.SignedLogRoot = nil
				return rsp
			}(testdata.DefaultTGlbrr(t, 0, 1)),
			wantErr: true,
		},
		{
			description: "invalid: bad Trillian response: no log root",
			req:         &types.GetEntriesV1{Start: 0, End: 1},
			rsp: func(rsp *trillian.GetLeavesByRangeResponse) *trillian.GetLeavesByRangeResponse {
				rsp.SignedLogRoot.LogRoot = nil
				return rsp
			}(testdata.DefaultTGlbrr(t, 0, 1)),
			wantErr: true,
		},
		{
			description: "invalid: bad Trillian response: truncated log root",
			req:         &types.GetEntriesV1{Start: 0, End: 1},
			rsp: func(rsp *trillian.GetLeavesByRangeResponse) *trillian.GetLeavesByRangeResponse {
				rsp.SignedLogRoot.LogRoot = rsp.SignedLogRoot.LogRoot[1:]
				return rsp
			}(testdata.DefaultTGlbrr(t, 0, 1)),
			wantErr: true,
		},
		{
			description: "invalid: bad Trillian response: too many leaves",
			req:         &types.GetEntriesV1{Start: 0, End: 1},
			rsp:         testdata.DefaultTGlbrr(t, 0, 2),
			wantErr:     true,
		},
		{
			description: "invalid: bad Trillian response: start is not a valid index",
			req:         &types.GetEntriesV1{Start: 10, End: 10},
			rsp:         testdata.DefaultTGlbrr(t, 9, 9),
			wantErr:     true,
		},
		{
			description: "invalid: bad Trillian response: invalid leaf indices",
			req:         &types.GetEntriesV1{Start: 10, End: 11},
			rsp:         testdata.DefaultTGlbrr(t, 11, 12),
			wantErr:     true,
		},
		{
			description: "valid",
			req:         &types.GetEntriesV1{Start: 10, End: 20},
			rsp:         testdata.DefaultTGlbrr(t, 10, 20),
		},
	} {
		err := checkGetLeavesByRange(table.req, table.rsp, table.err)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q", got, want, table.description)
		}
	}
}

func TestCheckGetInclusionProofByHash(t *testing.T) {
	for _, table := range []struct {
		description string
		rsp         *trillian.GetInclusionProofByHashResponse
		err         error
		wantErr     bool
	}{
		{
			description: "invalid: no Trillian response: error",
			err:         fmt.Errorf("backend failure"),
			wantErr:     true,
		},
		{
			description: "invalid: no Trillian response: nil",
			wantErr:     true,
		},
		{
			description: "invalid: bad Trillian response: no proofs",
			rsp:         &trillian.GetInclusionProofByHashResponse{},
			wantErr:     true,
		},
		{
			description: "bad response: no proof",
			rsp: func(rsp *trillian.GetInclusionProofByHashResponse) *trillian.GetInclusionProofByHashResponse {
				rsp.Proof[0] = nil
				return rsp
			}(testdata.DefaultTGipbhr(t)),
			wantErr: true,
		},
		{
			description: "bad response: proof with invalid node hash",
			rsp: func(rsp *trillian.GetInclusionProofByHashResponse) *trillian.GetInclusionProofByHashResponse {
				rsp.Proof[0].Hashes = append(rsp.Proof[0].Hashes, make([]byte, 0))
				return rsp
			}(testdata.DefaultTGipbhr(t)),
			wantErr: true,
		},
		{
			description: "valid",
			rsp:         testdata.DefaultTGipbhr(t),
		},
	} {
		err := checkGetInclusionProofByHash(newLogParameters(t, nil), table.rsp, table.err)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q", got, want, table.description)
		}
	}
}

func TestCheckGetConsistencyProof(t *testing.T) {
	for _, table := range []struct {
		description string
		rsp         *trillian.GetConsistencyProofResponse
		err         error
		wantErr     bool
	}{
		{
			description: "invalid: no Trillian response: error",
			err:         fmt.Errorf("backend failure"),
			wantErr:     true,
		},
		{
			description: "invalid: no Trillian response: nil",
			wantErr:     true,
		},
		{
			description: "invalid: bad Trillian response: no proof",
			rsp:         &trillian.GetConsistencyProofResponse{},
			wantErr:     true,
		},
		{
			description: "invalid: bad Trillian response: proof with invalid node hash",
			rsp: func(rsp *trillian.GetConsistencyProofResponse) *trillian.GetConsistencyProofResponse {
				rsp.Proof.Hashes = append(rsp.Proof.Hashes, make([]byte, 0))
				return rsp
			}(testdata.DefaultTGcpr(t)),
			wantErr: true,
		},
		{
			description: "valid",
			rsp:         testdata.DefaultTGcpr(t),
		},
	} {
		err := checkGetConsistencyProof(newLogParameters(t, nil), table.rsp, table.err)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q", got, want, table.description)
		}
	}
}

func TestCheckGetLatestSignedLogRoot(t *testing.T) {
	for _, table := range []struct {
		description string
		rsp         *trillian.GetLatestSignedLogRootResponse
		err         error
		wantErr     bool
	}{
		{
			description: "invalid: no Trillian response: error",
			err:         fmt.Errorf("backend failure"),
			wantErr:     true,
		},
		{
			description: "invalid: no Trillian response: nil",
			wantErr:     true,
		},
		{
			description: "invalid: bad Trillian response: no signed log root",
			rsp: func(rsp *trillian.GetLatestSignedLogRootResponse) *trillian.GetLatestSignedLogRootResponse {
				rsp.SignedLogRoot = nil
				return rsp
			}(testdata.DefaultTSlr(t)),
			wantErr: true,
		},
		{
			description: "invalid: bad Trillian response: no log root",
			rsp: func(rsp *trillian.GetLatestSignedLogRootResponse) *trillian.GetLatestSignedLogRootResponse {
				rsp.SignedLogRoot.LogRoot = nil
				return rsp
			}(testdata.DefaultTSlr(t)),
			wantErr: true,
		},
		{
			description: "invalid: bad Trillian response: truncated log root",
			rsp: func(rsp *trillian.GetLatestSignedLogRootResponse) *trillian.GetLatestSignedLogRootResponse {
				rsp.SignedLogRoot.LogRoot = rsp.SignedLogRoot.LogRoot[1:]
				return rsp
			}(testdata.DefaultTSlr(t)),
			wantErr: true,
		},
		{
			description: "invalid: bad Trillian response: truncated root hash",
			rsp:         testdata.Tslr(t, testdata.Tlr(t, testdata.TreeSize, testdata.Timestamp, make([]byte, 31))),
			wantErr:     true,
		},
		{
			description: "valid",
			rsp:         testdata.DefaultTSlr(t),
		},
	} {
		var lr ttypes.LogRootV1
		err := checkGetLatestSignedLogRoot(newLogParameters(t, nil), table.rsp, table.err, &lr)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q", got, want, table.description)
		}
	}
}
