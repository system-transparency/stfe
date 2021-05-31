package stfe

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	stfetypes "github.com/system-transparency/stfe/types"
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

func checkGetLeavesByRange(req *stfetypes.LeavesRequest, rsp *trillian.GetLeavesByRangeResponse, err error) error {
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
	if len(rsp.Leaves) == 0 {
		return fmt.Errorf("Trillian error: no leaves")
	}
	if len(rsp.Leaves) > int(req.EndSize-req.StartSize+1) {
		return fmt.Errorf("too many leaves: %d for [%d,%d]", len(rsp.Leaves), req.StartSize, req.EndSize)
	}

	// Ensure that a bad start parameter results in an error
	var lr types.LogRootV1
	if err := lr.UnmarshalBinary(rsp.SignedLogRoot.LogRoot); err != nil {
		return fmt.Errorf("cannot unmarshal log root: %v", err)
	}
	if uint64(req.StartSize) >= lr.TreeSize {
		return fmt.Errorf("invalid start(%d): tree size is %d", req.StartSize, lr.TreeSize)
	}

	// Ensure that we got and return expected leaf indices
	for i, leaf := range rsp.Leaves {
		if got, want := leaf.LeafIndex, int64(req.StartSize+uint64(i)); got != want {
			return fmt.Errorf("invalid leaf index(%d): wanted %d", got, want)
		}
	}
	return nil
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
