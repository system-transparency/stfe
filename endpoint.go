package stfe

import (
	"context"
	"fmt"
	"strings"

	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/system-transparency/stfe/types"
)

// Endpoint is a named HTTP API endpoint
type Endpoint string

const (
	EndpointAddEntry            = Endpoint("add-entry")
	EndpointAddCosignature      = Endpoint("add-cosignature")
	EndpointGetLatestSth        = Endpoint("get-latest-sth")
	EndpointGetStableSth        = Endpoint("get-stable-sth")
	EndpointGetCosignedSth      = Endpoint("get-cosigned-sth")
	EndpointGetProofByHash      = Endpoint("get-proof-by-hash")
	EndpointGetConsistencyProof = Endpoint("get-consistency-proof")
	EndpointGetEntries          = Endpoint("get-entries")
)

// Path joins a number of components to form a full endpoint path, e.g., base
// ("example.com"), prefix ("st/v1"), and the endpoint itself ("get-sth").
func (e Endpoint) Path(components ...string) string {
	return strings.Join(append(components, string(e)), "/")
}

func addEntry(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling add-entry request")
	item, err := i.LogParameters.parseAddEntryV1Request(r)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("parseAddEntryV1Request: %v", err)
	}
	leaf, err := types.Marshal(*item)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Marshal: %v", err) // should never happen
	}
	trsp, err := i.Client.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: i.LogParameters.TreeId,
		Leaf: &trillian.LogLeaf{
			LeafValue: leaf,
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
	costh, err := i.LogParameters.parseAddCosignatureV1Request(r)
	if err != nil {
		return http.StatusBadRequest, err
	}
	if err := i.SthSource.AddCosignature(ctx, costh); err != nil {
		return http.StatusBadRequest, err
	}
	return http.StatusOK, nil
}

func getLatestSth(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-latest-sth request")
	sth, err := i.SthSource.Latest(ctx)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Latest: %v", err)
	}
	if err := writeOctetResponse(w, *sth); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("writeOctetResponse: %v", err)
	}
	return http.StatusOK, nil
}

func getStableSth(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-stable-sth request")
	sth, err := i.SthSource.Stable(ctx)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Latest: %v", err)
	}
	if err := writeOctetResponse(w, *sth); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("writeOctetResponse: %v", err)
	}
	return http.StatusOK, nil
}

func getCosignedSth(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-cosigned-sth request")
	costh, err := i.SthSource.Cosigned(ctx)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Cosigned: %v", err)
	}
	if err := writeOctetResponse(w, *costh); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("writeOctetResponse: %v", err)
	}
	return http.StatusOK, nil
}

func getConsistencyProof(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-consistency-proof request")
	req, err := i.LogParameters.parseGetConsistencyProofV1Request(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	trsp, err := i.Client.GetConsistencyProof(ctx, &trillian.GetConsistencyProofRequest{
		LogId:          i.LogParameters.TreeId,
		FirstTreeSize:  int64(req.First),
		SecondTreeSize: int64(req.Second),
	})
	if errInner := checkGetConsistencyProof(i.LogParameters, trsp, err); errInner != nil {
		return http.StatusInternalServerError, fmt.Errorf("bad GetConsistencyProofResponse: %v", errInner)
	}

	if err := writeOctetResponse(w, *types.NewConsistencyProofV1(i.LogParameters.LogId, req.First, req.Second, NewNodePathFromHashPath(trsp.Proof.Hashes))); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("writeOctetResponse: %v", err)
	}
	return http.StatusOK, nil
}

func getProofByHash(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-proof-by-hash request")
	req, err := i.LogParameters.parseGetProofByHashV1Request(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	trsp, err := i.Client.GetInclusionProofByHash(ctx, &trillian.GetInclusionProofByHashRequest{
		LogId:           i.LogParameters.TreeId,
		LeafHash:        req.Hash[:],
		TreeSize:        int64(req.TreeSize),
		OrderBySequence: true,
	})
	if errInner := checkGetInclusionProofByHash(i.LogParameters, trsp, err); errInner != nil {
		return http.StatusInternalServerError, fmt.Errorf("bad GetInclusionProofByHashResponse: %v", errInner)
	}

	if err := writeOctetResponse(w, *types.NewInclusionProofV1(i.LogParameters.LogId, req.TreeSize, uint64(trsp.Proof[0].LeafIndex), NewNodePathFromHashPath(trsp.Proof[0].Hashes))); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("writeOctetResponse: %v", err)
	}
	return http.StatusOK, nil
}

func getEntries(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-entries request")
	req, err := i.LogParameters.parseGetEntriesV1Request(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	trsp, err := i.Client.GetLeavesByRange(ctx, &trillian.GetLeavesByRangeRequest{
		LogId:      i.LogParameters.TreeId,
		StartIndex: int64(req.Start),
		Count:      int64(req.End-req.Start) + 1,
	})
	if errInner := checkGetLeavesByRange(req, trsp, err); errInner != nil {
		return http.StatusInternalServerError, fmt.Errorf("checkGetLeavesByRangeResponse: %v", errInner) // there is one StatusBadRequest in here tho..
	}

	if rsp, err := NewStItemListFromLeaves(trsp.Leaves); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("NewStItemListFromLeaves: %v", err) // should never happen
	} else if err := writeOctetResponse(w, *rsp); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("writeOctetResponse: %v", err)
	}
	return http.StatusOK, nil
}

func writeOctetResponse(w http.ResponseWriter, i interface{}) error {
	b, err := types.Marshal(i)
	if err != nil {
		return fmt.Errorf("Marshal: %v", err)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("Write: %v", err)
	}
	return nil
}
