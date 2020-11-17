package stfe

import (
	"fmt"

	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
)

func checkQueueLeaf(rsp *trillian.QueueLeafResponse, err error) (int, error) {
	if err != nil || rsp == nil || rsp.QueuedLeaf == nil {
		return http.StatusInternalServerError, fmt.Errorf("%v", err)
	}
	if codes.Code(rsp.QueuedLeaf.GetStatus().GetCode()) == codes.AlreadyExists {
		// no need to report this as an invalid request, just (re)issue sdi
		glog.V(3).Infof("queued leaf is a duplicate => %X", rsp.QueuedLeaf.Leaf.LeafValue)
	}
	return 0, nil
}

func checkGetLeavesByRange(req *GetEntriesRequest, rsp *trillian.GetLeavesByRangeResponse, err error) (int, error) {
	if err != nil || rsp == nil || len(rsp.Leaves) == 0 || rsp.SignedLogRoot == nil || rsp.SignedLogRoot.LogRoot == nil {
		return http.StatusInternalServerError, fmt.Errorf("%v", err)
	}
	if len(rsp.Leaves) > int(req.End-req.Start+1) {
		return http.StatusInternalServerError, fmt.Errorf("too many leaves: %d for [%d,%d]", len(rsp.Leaves), req.Start, req.End)
	}

	// Ensure that a bad start parameter results in an error
	var lr types.LogRootV1
	if err := lr.UnmarshalBinary(rsp.SignedLogRoot.LogRoot); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("cannot unmarshal log root: %v", err)
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

func checkGetInclusionProofByHash(lp *LogParameters, rsp *trillian.GetInclusionProofByHashResponse, err error) (int, error) {
	if err != nil || rsp == nil || len(rsp.Proof) == 0 || rsp.Proof[0] == nil {
		return http.StatusInternalServerError, fmt.Errorf("%v", err)
	}
	return checkHashPath(lp.HashType.Size(), rsp.Proof[0].Hashes)
}

func checkGetConsistencyProof(lp *LogParameters, rsp *trillian.GetConsistencyProofResponse, err error) (int, error) {
	if err != nil || rsp == nil || rsp.Proof == nil {
		return http.StatusInternalServerError, fmt.Errorf("%v", err)
	}
	return checkHashPath(lp.HashType.Size(), rsp.Proof.Hashes)
}

func checkGetLatestSignedLogRoot(lp *LogParameters, rsp *trillian.GetLatestSignedLogRootResponse, err error, out *types.LogRootV1) (int, error) {
	if err != nil || rsp == nil || rsp.SignedLogRoot == nil || rsp.SignedLogRoot.LogRoot == nil {
		return http.StatusInternalServerError, fmt.Errorf("%v", err)
	}
	if err := out.UnmarshalBinary(rsp.SignedLogRoot.LogRoot); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("cannot unmarshal log root: %v", err)
	}
	if len(out.RootHash) != lp.HashType.Size() {
		return http.StatusInternalServerError, fmt.Errorf("invalid root hash: %v", out.RootHash)
	}
	return 0, nil
}

func checkHashPath(hashSize int, path [][]byte) (int, error) {
	for _, hash := range path {
		if len(hash) != hashSize {
			return http.StatusInternalServerError, fmt.Errorf("invalid proof: %v", path)
		}
	}
	return 0, nil
}
