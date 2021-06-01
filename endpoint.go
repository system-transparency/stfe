package stfe

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/system-transparency/stfe/types"
)

func addEntry(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling add-entry request")
	leaf, err := i.LogParameters.parseAddEntryV1Request(r)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("parseAddEntryV1Request: %v", err)
	}
	trsp, err := i.Client.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: i.LogParameters.TreeId,
		Leaf: &trillian.LogLeaf{
			LeafValue: leaf.Marshal(),
			ExtraData: nil,
		},
	})
	if errInner := checkQueueLeaf(trsp, err); errInner != nil {
		return http.StatusInternalServerError, fmt.Errorf("bad QueueLeafResponse: %v", errInner)
	}
	return http.StatusOK, nil
}

func addCosignature(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling add-cosignature request")
	req, err := i.LogParameters.parseAddCosignatureRequest(r)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("parseAddCosignatureRequest: %v", err)
	}
	vk := i.LogParameters.Witnesses[*req.KeyHash]
	if err := i.SthSource.AddCosignature(ctx, ed25519.PublicKey(vk[:]), req.Signature); err != nil {
		return http.StatusBadRequest, fmt.Errorf("AddCosignature: %v", err)
	}
	return http.StatusOK, nil
}

func getLatestSth(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-latest-sth request")
	sth, err := i.SthSource.Latest(ctx)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Latest: %v", err)
	}
	if err := sth.MarshalASCII(w); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("MarshalASCII: %v", err)
	}
	return http.StatusOK, nil
}

func getStableSth(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-stable-sth request")
	sth, err := i.SthSource.Stable(ctx)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Latest: %v", err)
	}
	if err := sth.MarshalASCII(w); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("MarshalASCII: %v", err)
	}
	return http.StatusOK, nil
}

func getCosignedSth(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-cosigned-sth request")
	sth, err := i.SthSource.Cosigned(ctx)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Cosigned: %v", err)
	}
	if err := sth.MarshalASCII(w); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("MarshalASCII: %v", err)
	}
	return http.StatusOK, nil
}

func getConsistencyProof(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-consistency-proof request")
	req, err := i.LogParameters.parseGetConsistencyProofRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	trsp, err := i.Client.GetConsistencyProof(ctx, &trillian.GetConsistencyProofRequest{
		LogId:          i.LogParameters.TreeId,
		FirstTreeSize:  int64(req.OldSize),
		SecondTreeSize: int64(req.NewSize),
	})
	if errInner := checkGetConsistencyProof(i.LogParameters, trsp, err); errInner != nil {
		return http.StatusInternalServerError, fmt.Errorf("bad GetConsistencyProofResponse: %v", errInner)
	}

	proof := &types.ConsistencyProof{
		NewSize: req.NewSize,
		OldSize: req.OldSize,
		Path:    NodePathFromHashes(trsp.Proof.Hashes),
	}
	if err := proof.MarshalASCII(w); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("MarshalASCII: %v", err)
	}
	return http.StatusOK, nil
}

func getProofByHash(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-proof-by-hash request")
	req, err := i.LogParameters.parseGetProofByHashRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	trsp, err := i.Client.GetInclusionProofByHash(ctx, &trillian.GetInclusionProofByHashRequest{
		LogId:           i.LogParameters.TreeId,
		LeafHash:        req.LeafHash[:],
		TreeSize:        int64(req.TreeSize),
		OrderBySequence: true,
	})
	if errInner := checkGetInclusionProofByHash(i.LogParameters, trsp, err); errInner != nil {
		return http.StatusInternalServerError, fmt.Errorf("bad GetInclusionProofByHashResponse: %v", errInner)
	}

	proof := &types.InclusionProof{
		TreeSize:  req.TreeSize,
		LeafIndex: uint64(trsp.Proof[0].LeafIndex),
		Path:      NodePathFromHashes(trsp.Proof[0].Hashes),
	}
	if err := proof.MarshalASCII(w); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("MarshalASCII: %v", err)
	}
	return http.StatusOK, nil
}

func getEntries(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-entries request")
	req, err := i.LogParameters.parseGetEntriesRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	trsp, err := i.Client.GetLeavesByRange(ctx, &trillian.GetLeavesByRangeRequest{
		LogId:      i.LogParameters.TreeId,
		StartIndex: int64(req.StartSize),
		Count:      int64(req.EndSize-req.StartSize) + 1,
	})
	if errInner := checkGetLeavesByRange(req, trsp, err); errInner != nil {
		return http.StatusInternalServerError, fmt.Errorf("checkGetLeavesByRangeResponse: %v", errInner) // there is one StatusBadRequest in here tho..
	}

	for _, serialized := range trsp.Leaves {
		var leaf types.Leaf
		if err := leaf.Unmarshal(serialized.LeafValue); err != nil {
			return http.StatusInternalServerError, fmt.Errorf("Unmarshal: %v", err)
		}
		if err := leaf.MarshalASCII(w); err != nil {
			return http.StatusInternalServerError, fmt.Errorf("MarshalASCII: %v", err)
		}
	}
	return http.StatusOK, nil
}
