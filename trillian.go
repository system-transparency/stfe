package stfe

import (
	"fmt"

	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
)

func checkQueueLeaf(rsp *trillian.QueueLeafResponse) (int, error) {
	if codes.Code(rsp.QueuedLeaf.GetStatus().GetCode()) == codes.AlreadyExists {
		// no need to report this as an invalid request, just (re)issue sdi
		glog.V(3).Infof("queued leaf is a duplicate => %X", rsp.QueuedLeaf.Leaf.LeafValue)
	} else {
		glog.V(3).Infof("queued leaf => %X", rsp.QueuedLeaf.Leaf.LeafValue)
	}
	return 0, nil
}

func checkGetLeavesByRange(rsp *trillian.GetLeavesByRangeResponse, req *GetEntriesRequest) (int, error) {
	if len(rsp.Leaves) > int(req.End-req.Start+1) {
		return http.StatusInternalServerError, fmt.Errorf("backend GetLeavesByRange returned too many leaves: %d for [%d,%d]", len(rsp.Leaves), req.Start, req.End)
	}

	// Ensure that a bad start parameter results in an error
	var lr types.LogRootV1
	if err := lr.UnmarshalBinary(rsp.GetSignedLogRoot().GetLogRoot()); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed unmarshaling log root: %v", err)
	}
	if uint64(req.Start) >= lr.TreeSize {
		return http.StatusNotFound, fmt.Errorf("invalid start(%d): tree size is %d", req.Start, lr.TreeSize)
	}

	// Ensure that we got and return expected leaf indices
	for i, leaf := range rsp.Leaves {
		if leaf.LeafIndex != req.Start+int64(i) {
			return http.StatusInternalServerError, fmt.Errorf("invalid leaf index: wanted %d, got %d", req.Start+int64(i), leaf.LeafIndex)
		}
	}
	return 0, nil
}

func checkGetInclusionProofByHash(rsp *trillian.GetInclusionProofByHashResponse, lp *LogParameters) (int, error) {
	if rsp.Proof == nil || len(rsp.Proof) == 0 {
		return http.StatusNotFound, fmt.Errorf("incomplete backend response")
	} // maybe redundant, but better safe than sorry
	return checkHashPath(lp.HashType.Size(), rsp.Proof[0].Hashes)
}

func checkGetConsistencyProofResponse(rsp *trillian.GetConsistencyProofResponse, lp *LogParameters) (int, error) {
	if rsp.Proof == nil {
		return http.StatusNotFound, fmt.Errorf("incomplete backend response")
	} // not redundant, out-of-range parameters yield an empty proof w/o error
	return checkHashPath(lp.HashType.Size(), rsp.Proof.Hashes)
}

func checkTrillianGetLatestSignedLogRoot(rsp *trillian.GetLatestSignedLogRootResponse, lp *LogParameters) (int, error) {
	if rsp.SignedLogRoot == nil {
		return http.StatusInternalServerError, fmt.Errorf("incomplete backend response")
	} // maybe redundant

	var lr types.LogRootV1
	if err := lr.UnmarshalBinary(rsp.GetSignedLogRoot().GetLogRoot()); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed unmarshaling log root: %v", err)
	}
	if len(lr.RootHash) != lp.HashType.Size() {
		return http.StatusInternalServerError, fmt.Errorf("invalid root hash: %v", lr.RootHash)
	} // maybe redundant, but would not necessarily be caught by marshal error
	return 0, nil
}

func checkHashPath(hashSize int, path [][]byte) (int, error) {
	for _, hash := range path {
		if len(hash) != hashSize {
			return http.StatusInternalServerError, fmt.Errorf("invalid proof: %v", path)
		}
	} // maybe redundant, but would not necessarily be caught by marshal error
	return 0, nil
}
