package stfe

import (
	"context"
	"fmt"

	"encoding/json"
	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
)

// appHandler implements the http.Handler interface, and contains a reference
// to an STFE server instance as well as a function that uses it.
type appHandler struct {
	instance *instance // STFE server instance
	endpoint string    // e.g., add-entry
	method   string    // e.g., GET
	handler  func(context.Context, *instance, http.ResponseWriter, *http.Request) (int, error)
}

// ServeHTTP docdoc
func (a appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithDeadline(r.Context(), a.instance.timesource.Now().Add(a.instance.deadline))
	defer cancel()

	if r.Method != a.method {
		glog.Warningf("%s: got HTTP %s, wanted HTTP %s", a.instance.prefix+a.endpoint, r.Method, a.method)
		a.sendHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed: %s", r.Method))
		return
	}

	statusCode, err := a.handler(ctx, a.instance, w, r)
	if err != nil {
		glog.Warningf("handler error %s/%s: %v", a.instance.prefix, a.endpoint, err)
		a.sendHTTPError(w, statusCode, err)
	}
}

// sendHTTPError replies to a request with an error message and a status code.
func (a appHandler) sendHTTPError(w http.ResponseWriter, statusCode int, err error) {
	http.Error(w, http.StatusText(statusCode), statusCode)
}

func addEntry(ctx context.Context, i *instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in addEntry")
	request, err := NewAddEntryRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	} // request can be decoded

	leaf, err := VerifyAddEntryRequest(request)
	if err != nil {
		return http.StatusBadRequest, err
	} // leaf is valid, e.g., signed by a trust anchor

	trillianRequest := trillian.QueueLeafRequest{
		LogId: i.logID,
		Leaf: &trillian.LogLeaf{
			LeafValue: leaf,
			//TODO: add appendix here w/ chain + signature
		},
	}
	trillianResponse, err := i.client.QueueLeaf(ctx, &trillianRequest)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("backend QueueLeaf request failed: %v", err)
	} // note: more detail could be provided here, see addChainInternal in ctfe 
	glog.Infof("Queued leaf: %v", trillianResponse.QueuedLeaf.Leaf.LeafValue)

	// TODO: respond with an SDI
	return http.StatusOK, nil
}

// getEntries provides a list of entries from the Trillian backend
func getEntries(ctx context.Context, i *instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in getEntries")
	request, err := NewGetEntriesRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	} // request can be decoded and is valid

	trillianRequest := trillian.GetLeavesByRangeRequest{
		LogId:      i.logID,
		StartIndex: request.Start,
		Count:      request.End - request.Start + 1,
	}
	trillianResponse, err := i.client.GetLeavesByRange(ctx, &trillianRequest)
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

		glog.Infof("Entry(%d) => %v", request.Start+int64(i), leaf.GetLeafValue())
	}
	// TODO: use the returned root for tree_size santity checking against start?

	w.Header().Set("Content-Type", "application/json")
	data, err := NewGetEntriesResponse(trillianResponse.Leaves)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed createing GetEntriesResponse: %v", err)
	}
	json, err := json.Marshal(&data)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed json-encoding GetEntriesResponse: %v", err)
	}
	_, err = w.Write(json)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed writing get-entries response: %v", err)
	}
	return http.StatusOK, nil
}

// getAnchors provides a list of configured trust anchors
func getAnchors(ctx context.Context, i *instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in getAnchors")
	return http.StatusOK, nil // TODO
}

// getProofByHash provides an inclusion proof based on a given leaf hash
func getProofByHash(ctx context.Context, i *instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in getProofByHash")
	request, err := NewGetProofByHashRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	} // request can be decoded and is valid

	trillianRequest := trillian.GetInclusionProofByHashRequest{
		LogId:           i.logID,
		LeafHash:        request.Hash,
		TreeSize:        request.TreeSize,
		OrderBySequence: true,
	}
	trillianResponse, err := i.client.GetInclusionProofByHash(ctx, &trillianRequest)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed fetching inclusion proof from Trillian backend: %v", err)
	}
	// TODO: check the returned tree size in response?

	// Santity check
	if len(trillianResponse.Proof) == 0 {
		return http.StatusNotFound, fmt.Errorf("get-proof-by-hash backend returned no proof")
	}
	// TODO: verify that proof is valid?

	w.Header().Set("Content-Type", "application/json")
	data, err := NewGetProofByHashResponse(uint64(request.TreeSize), trillianResponse.Proof[0])
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed creating get-proof-by-hash response: %v", err)
	}
	json, err := json.Marshal(data)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed json-encoding GetProofByHashResponse: %v", err)
	}
	_, err = w.Write(json)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed writing get-entries response: %v", err)
	}

	return http.StatusOK, nil // TODO
}

// getConsistencyProof provides a consistency proof between two STHs
func getConsistencyProof(ctx context.Context, i *instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in getConsistencyProof")
	return http.StatusOK, nil // TODO
}

// getSth provides the most recent STH
func getSth(ctx context.Context, i *instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in getSth")
	return http.StatusOK, nil // TODO
}
