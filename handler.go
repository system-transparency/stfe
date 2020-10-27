package stfe

import (
	"context"
	"fmt"
	"time"

	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
)

// appHandler implements the http.Handler interface, and contains a reference
// to an STFE server instance as well as a function that uses it.
type appHandler struct {
	instance *Instance // STFE server instance
	endpoint string    // e.g., add-entry
	method   string    // e.g., GET
	handler  func(context.Context, *Instance, http.ResponseWriter, *http.Request) (int, error)
}

// ServeHTTP docdoc
func (a appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithDeadline(r.Context(), time.Now().Add(a.instance.Deadline))
	defer cancel()

	if r.Method != a.method {
		glog.Warningf("%s: got HTTP %s, wanted HTTP %s", a.instance.LogParameters.Prefix+a.endpoint, r.Method, a.method)
		a.sendHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed: %s", r.Method))
		return
	}

	statusCode, err := a.handler(ctx, a.instance, w, r)
	if err != nil {
		glog.Warningf("handler error %s/%s: %v", a.instance.LogParameters.Prefix, a.endpoint, err)
		a.sendHTTPError(w, statusCode, err)
	}
}

// sendHTTPError replies to a request with an error message and a status code.
func (a appHandler) sendHTTPError(w http.ResponseWriter, statusCode int, err error) {
	http.Error(w, http.StatusText(statusCode), statusCode)
}

func addEntry(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in addEntry")
	request, err := NewAddEntryRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	} // request can be decoded

	leaf, appendix, err := VerifyAddEntryRequest(i.LogParameters, request)
	if err != nil {
		return http.StatusBadRequest, err
	} // valid add-entry request

	trillianRequest := trillian.QueueLeafRequest{
		LogId: i.LogParameters.TreeId,
		Leaf: &trillian.LogLeaf{
			LeafValue: leaf,
			ExtraData: appendix,
		},
	}
	trillianResponse, err := i.Client.QueueLeaf(ctx, &trillianRequest)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("backend QueueLeaf request failed: %v", err)
	} // note: more detail could be provided here, see addChainInternal in ctfe
	glog.Infof("Queued leaf: %v", trillianResponse.QueuedLeaf.Leaf.LeafValue)

	sdi, err := GenV1SDI(i.LogParameters, trillianResponse.QueuedLeaf.Leaf.LeafValue)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed creating signed debug info: %v", err)
	}

	response, err := NewAddEntryResponse(sdi)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed creating AddEntryResponse: %v", err)
	}
	if err := WriteJsonResponse(response, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getEntries provides a list of entries from the Trillian backend
func getEntries(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in getEntries")
	request, err := NewGetEntriesRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	} // request can be decoded and is valid

	trillianRequest := trillian.GetLeavesByRangeRequest{
		LogId:      i.LogParameters.TreeId,
		StartIndex: request.Start,
		Count:      request.End - request.Start + 1,
	}
	trillianResponse, err := i.Client.GetLeavesByRange(ctx, &trillianRequest)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("backend GetLeavesByRange request failed: %v", err)
	}

	// Santity check
	if len(trillianResponse.Leaves) > int(request.End-request.Start+1) {
		return http.StatusInternalServerError, fmt.Errorf("backend GetLeavesByRange returned too many leaves: %d for [%d,%d]", len(trillianResponse.Leaves), request.Start, request.End)
	}
	for i, leaf := range trillianResponse.Leaves {
		if leaf.LeafIndex != request.Start+int64(i) {
			return http.StatusInternalServerError, fmt.Errorf("backend GetLeavesByRange returned unexpected leaf index: wanted %d, got %d", request.Start+int64(i), leaf.LeafIndex)
		}

		glog.Infof("Leaf(%d) => %v", request.Start+int64(i), leaf.GetLeafValue())
	}
	// TODO: use the returned root for tree_size santity checking against start?

	response, err := NewGetEntriesResponse(trillianResponse.Leaves)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed creating GetEntriesResponse: %v", err)
	}
	if err := WriteJsonResponse(response, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getAnchors provides a list of configured trust anchors
func getAnchors(_ context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.Info("in getAnchors")
	data := NewGetAnchorsResponse(i.LogParameters.AnchorList)
	if err := WriteJsonResponse(data, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getProofByHash provides an inclusion proof based on a given leaf hash
func getProofByHash(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in getProofByHash")
	request, err := NewGetProofByHashRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	} // request can be decoded and is valid

	trillianRequest := trillian.GetInclusionProofByHashRequest{
		LogId:           i.LogParameters.TreeId,
		LeafHash:        request.Hash,
		TreeSize:        request.TreeSize,
		OrderBySequence: true,
	}
	trillianResponse, err := i.Client.GetInclusionProofByHash(ctx, &trillianRequest)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed fetching inclusion proof from Trillian backend: %v", err)
	}
	// TODO: check the returned tree size in response?

	// Santity check
	if len(trillianResponse.Proof) == 0 {
		return http.StatusNotFound, fmt.Errorf("get-proof-by-hash backend returned no proof")
	}
	// TODO: verify that proof is valid?

	response, err := NewGetProofByHashResponse(uint64(request.TreeSize), trillianResponse.Proof[0])
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed creating get-proof-by-hash response: %v", err)
	}
	if err := WriteJsonResponse(response, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getConsistencyProof provides a consistency proof between two STHs
func getConsistencyProof(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in getConsistencyProof")
	return http.StatusOK, nil // TODO
}

// getSth provides the most recent STH
func getSth(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in getSth")
	return http.StatusOK, nil // TODO
}
