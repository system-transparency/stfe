package stfe

import (
	"fmt"

	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
)

func checkQueueLeaf(rsp *trillian.QueueLeafResponse, err error) error {
	if err != nil {
		return fmt.Errorf("Trillian error: %v", err)
	}
	if rsp == nil {
		return fmt.Errorf("Trillian error: empty response")
	}
	if rsp.QueuedLeaf == nil {
		return fmt.Errorf("Trillian error: empty QueuedLeaf")
	}
	if codes.Code(rsp.QueuedLeaf.GetStatus().GetCode()) == codes.AlreadyExists {
		glog.V(3).Infof("queued leaf is a duplicate => %X", rsp.QueuedLeaf.Leaf.LeafValue)
	}
	return nil
}

func checkGetLeavesByRange(req *GetEntriesRequest, rsp *trillian.GetLeavesByRangeResponse, err error) (int, error) {
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Trillian Error: %v", err)
	}
	if rsp == nil {
		return http.StatusInternalServerError, fmt.Errorf("Trillian error: empty response")
	}
	if rsp.SignedLogRoot == nil {
		return http.StatusInternalServerError, fmt.Errorf("Trillian error: no signed log root")
	}
	if rsp.SignedLogRoot.LogRoot == nil {
		return http.StatusInternalServerError, fmt.Errorf("Trillian error: no log root")
	}
	if len(rsp.Leaves) == 0 {
		return http.StatusInternalServerError, fmt.Errorf("Trillian error: no leaves")
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
	return http.StatusOK, nil
}

func checkGetInclusionProofByHash(lp *LogParameters, rsp *trillian.GetInclusionProofByHashResponse, err error) error {
	if err != nil {
		return fmt.Errorf("Trillian Error: %v", err)
	}
	if rsp == nil {
		return fmt.Errorf("Trillian error: empty response")
	}
	if len(rsp.Proof) == 0 {
		return fmt.Errorf("Trillian error: no proofs")
	}
	if rsp.Proof[0] == nil {
		return fmt.Errorf("Trillian error: no proof")
	}
	return checkHashPath(lp.HashType.Size(), rsp.Proof[0].Hashes)
}

func checkGetConsistencyProof(lp *LogParameters, rsp *trillian.GetConsistencyProofResponse, err error) error {
	if err != nil {
		return fmt.Errorf("Trillian Error: %v", err)
	}
	if rsp == nil {
		return fmt.Errorf("Trillian error: empty response")
	}
	if rsp.Proof == nil {
		return fmt.Errorf("Trillian error: no proof")
	}
	return checkHashPath(lp.HashType.Size(), rsp.Proof.Hashes)
}

func checkGetLatestSignedLogRoot(lp *LogParameters, rsp *trillian.GetLatestSignedLogRootResponse, err error, out *types.LogRootV1) error {
	if err != nil {
		return fmt.Errorf("Trillian Error: %v", err)
	}
	if rsp == nil {
		return fmt.Errorf("Trillian error: empty response")
	}
	if rsp.SignedLogRoot == nil {
		return fmt.Errorf("Trillian error: no signed log root")
	}
	if rsp.SignedLogRoot.LogRoot == nil {
		return fmt.Errorf("Trillian error: no log root")
	}
	if err := out.UnmarshalBinary(rsp.SignedLogRoot.LogRoot); err != nil {
		return fmt.Errorf("cannot unmarshal log root: %v", err)
	}
	if len(out.RootHash) != lp.HashType.Size() {
		return fmt.Errorf("invalid root hash: %v", out.RootHash)
	}
	return nil
}

func checkHashPath(hashSize int, path [][]byte) error {
	for _, hash := range path {
		if len(hash) != hashSize {
			return fmt.Errorf("invalid proof: %v", path)
		}
	}
	return nil
}
