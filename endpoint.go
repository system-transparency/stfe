package stfe

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/system-transparency/stfe/types"
)

// Endpoint is a named HTTP API endpoint
type Endpoint string

const (
	EndpointAddEntry            = Endpoint("add-leaf")
	EndpointAddCosignature      = Endpoint("add-cosignature")
	EndpointGetLatestSth        = Endpoint("get-tree-head-latest")
	EndpointGetStableSth        = Endpoint("get-tree-head-to-sign")
	EndpointGetCosignedSth      = Endpoint("get-tree-head-cosigned")
	EndpointGetProofByHash      = Endpoint("get-proof-by-hash")
	EndpointGetConsistencyProof = Endpoint("get-consistency-proof")
	EndpointGetEntries          = Endpoint("get-leaves")
)

// Path joins a number of components to form a full endpoint path, e.g., base
// ("example.com"), prefix ("st/v1"), and the endpoint itself ("get-sth").
func (e Endpoint) Path(components ...string) string {
	return strings.Join(append(components, string(e)), "/")
}

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

//func getProofByHash(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
//	glog.V(3).Info("handling get-proof-by-hash request")
//	req, err := i.LogParameters.parseGetProofByHashV1Request(r)
//	if err != nil {
//		return http.StatusBadRequest, err
//	}
//
//	trsp, err := i.Client.GetInclusionProofByHash(ctx, &trillian.GetInclusionProofByHashRequest{
//		LogId:           i.LogParameters.TreeId,
//		LeafHash:        req.Hash[:],
//		TreeSize:        int64(req.TreeSize),
//		OrderBySequence: true,
//	})
//	if errInner := checkGetInclusionProofByHash(i.LogParameters, trsp, err); errInner != nil {
//		return http.StatusInternalServerError, fmt.Errorf("bad GetInclusionProofByHashResponse: %v", errInner)
//	}
//
//	if err := writeOctetResponse(w, *types.NewInclusionProofV1(i.LogParameters.LogId, req.TreeSize, uint64(trsp.Proof[0].LeafIndex), NewNodePathFromHashPath(trsp.Proof[0].Hashes))); err != nil {
//		return http.StatusInternalServerError, fmt.Errorf("writeOctetResponse: %v", err)
//	}
//	return http.StatusOK, nil
//}
//
//func getEntries(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
//	glog.V(3).Info("handling get-entries request")
//	req, err := i.LogParameters.parseGetEntriesV1Request(r)
//	if err != nil {
//		return http.StatusBadRequest, err
//	}
//
//	trsp, err := i.Client.GetLeavesByRange(ctx, &trillian.GetLeavesByRangeRequest{
//		LogId:      i.LogParameters.TreeId,
//		StartIndex: int64(req.Start),
//		Count:      int64(req.End-req.Start) + 1,
//	})
//	if errInner := checkGetLeavesByRange(req, trsp, err); errInner != nil {
//		return http.StatusInternalServerError, fmt.Errorf("checkGetLeavesByRangeResponse: %v", errInner) // there is one StatusBadRequest in here tho..
//	}
//
//	if rsp, err := NewStItemListFromLeaves(trsp.Leaves); err != nil {
//		return http.StatusInternalServerError, fmt.Errorf("NewStItemListFromLeaves: %v", err) // should never happen
//	} else if err := writeOctetResponse(w, *rsp); err != nil {
//		return http.StatusInternalServerError, fmt.Errorf("writeOctetResponse: %v", err)
//	}
//	return http.StatusOK, nil
//}
//
//func writeOctetResponse(w http.ResponseWriter, i interface{}) error {
//	b, err := types.Marshal(i)
//	if err != nil {
//		return fmt.Errorf("Marshal: %v", err)
//	}
//	w.Header().Set("Content-Type", "application/octet-stream")
//	if _, err := w.Write(b); err != nil {
//		return fmt.Errorf("Write: %v", err)
//	}
//	return nil
//}
