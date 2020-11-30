package stfe

import (
	"context"
	"fmt"
	"time"

	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
)

// handler implements the http.Handler interface, and contains a reference
// to an STFE server instance as well as a function that uses it.
type handler struct {
	instance *Instance // STFE server instance
	endpoint Endpoint  // e.g., add-entry
	method   string    // e.g., GET
	handler  func(context.Context, *Instance, http.ResponseWriter, *http.Request) (int, error)
}

func (a handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// export prometheus metrics
	var now time.Time = time.Now()
	var statusCode int
	defer func() {
		rspcnt.Inc(a.instance.LogParameters.id(), a.endpoint.String(), fmt.Sprintf("%d", statusCode))
		latency.Observe(time.Now().Sub(now).Seconds(), a.instance.LogParameters.id(), a.endpoint.String(), fmt.Sprintf("%d", statusCode))
	}()
	reqcnt.Inc(a.instance.LogParameters.id(), a.endpoint.String())

	ctx, cancel := context.WithDeadline(r.Context(), now.Add(a.instance.Deadline))
	defer cancel()

	if r.Method != a.method {
		glog.Warningf("%s: got HTTP %s, wanted HTTP %s", a.instance.LogParameters.Prefix+a.endpoint.String(), r.Method, a.method)
		a.sendHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed: %s", r.Method))
		return
	}

	statusCode, err := a.handler(ctx, a.instance, w, r)
	if err != nil {
		glog.Warningf("handler error %s/%s: %v", a.instance.LogParameters.Prefix, a.endpoint, err)
		a.sendHTTPError(w, statusCode, err)
	}
}

func (a handler) sendHTTPError(w http.ResponseWriter, statusCode int, err error) {
	http.Error(w, http.StatusText(statusCode), statusCode)
}

func addEntry(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling add-entry request")
	leaf, appendix, err := i.LogParameters.newAddEntryRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	trsp, err := i.Client.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: i.LogParameters.TreeId,
		Leaf: &trillian.LogLeaf{
			LeafValue: leaf,
			ExtraData: appendix,
		},
	})
	if errInner := checkQueueLeaf(trsp, err); errInner != nil {
		return http.StatusInternalServerError, fmt.Errorf("bad QueueLeafResponse: %v", errInner)
	}

	sdi, err := i.LogParameters.genV1Sdi(trsp.QueuedLeaf.Leaf.LeafValue)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed creating signed debug info: %v", err)
	}
	rsp, err := sdi.MarshalB64()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := writeJsonResponse(rsp, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getEntries provides a list of entries from the Trillian backend
func getEntries(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-entries request")
	req, err := i.LogParameters.newGetEntriesRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	trsp, err := i.Client.GetLeavesByRange(ctx, &trillian.GetLeavesByRangeRequest{
		LogId:      i.LogParameters.TreeId,
		StartIndex: req.Start,
		Count:      req.End - req.Start + 1,
	})
	if status, errInner := checkGetLeavesByRange(req, trsp, err); errInner != nil {
		return status, fmt.Errorf("bad GetLeavesByRangeResponse: %v", errInner)
	}

	rsp, err := i.LogParameters.newGetEntriesResponse(trsp.Leaves)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed creating GetEntriesResponse: %v", err)
	}
	if err := writeJsonResponse(rsp, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getAnchors provides a list of configured trust anchors
func getAnchors(_ context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-anchors request")
	data := i.LogParameters.newGetAnchorsResponse()
	if err := writeJsonResponse(data, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getProofByHash provides an inclusion proof based on a given leaf hash
func getProofByHash(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-proof-by-hash request")
	req, err := i.LogParameters.newGetProofByHashRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	trsp, err := i.Client.GetInclusionProofByHash(ctx, &trillian.GetInclusionProofByHashRequest{
		LogId:           i.LogParameters.TreeId,
		LeafHash:        req.Hash,
		TreeSize:        req.TreeSize,
		OrderBySequence: true,
	})
	if errInner := checkGetInclusionProofByHash(i.LogParameters, trsp, err); errInner != nil {
		return http.StatusInternalServerError, fmt.Errorf("bad GetInclusionProofByHashResponse: %v", errInner)
	}

	rsp, err := NewInclusionProofV1(i.LogParameters.LogId, uint64(req.TreeSize), uint64(trsp.Proof[0].LeafIndex), trsp.Proof[0].Hashes).MarshalB64()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := writeJsonResponse(rsp, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getConsistencyProof provides a consistency proof between two STHs
func getConsistencyProof(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-consistency-proof request")
	req, err := i.LogParameters.newGetConsistencyProofRequest(r)
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

	rsp, err := NewConsistencyProofV1(i.LogParameters.LogId, uint64(req.First), uint64(req.Second), trsp.Proof.Hashes).MarshalB64()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := writeJsonResponse(rsp, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getSth provides the most recent STH
func getSth(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-sth request")
	trsp, err := i.Client.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{
		LogId: i.LogParameters.TreeId,
	})
	var lr types.LogRootV1
	if errInner := checkGetLatestSignedLogRoot(i.LogParameters, trsp, err, &lr); errInner != nil {
		return http.StatusInternalServerError, fmt.Errorf("bad GetLatestSignedLogRootResponse: %v", errInner)
	}

	sth, err := i.LogParameters.genV1Sth(NewTreeHeadV1(&lr))
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed creating signed tree head: %v", err)
	}
	rsp, err := sth.MarshalB64()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := writeJsonResponse(rsp, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}
