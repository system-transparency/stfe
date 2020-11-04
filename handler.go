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

func (a appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// export prometheus metrics
	var now time.Time = time.Now()
	var statusCode int
	defer func() {
		rspcnt.Inc(a.instance.LogParameters.id(), a.endpoint, fmt.Sprintf("%d", statusCode))
		latency.Observe(time.Now().Sub(now).Seconds(), a.instance.LogParameters.id(), a.endpoint, fmt.Sprintf("%d", statusCode))
	}()
	reqcnt.Inc(a.instance.LogParameters.id(), a.endpoint)

	ctx, cancel := context.WithDeadline(r.Context(), now.Add(a.instance.Deadline))
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

func (a appHandler) sendHTTPError(w http.ResponseWriter, statusCode int, err error) {
	http.Error(w, http.StatusText(statusCode), statusCode)
}

func addEntry(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling add-entry request")
	leaf, appendix, err := NewAddEntryRequest(i.LogParameters, r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	treq := trillian.QueueLeafRequest{
		LogId: i.LogParameters.TreeId,
		Leaf: &trillian.LogLeaf{
			LeafValue: leaf,
			ExtraData: appendix,
		},
	}
	trsp, err := i.Client.QueueLeaf(ctx, &treq)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("backend QueueLeaf request failed: %v", err)
	}
	if status, err := checkQueueLeaf(trsp); err != nil {
		return status, err
	}

	sdi, err := GenV1SDI(i.LogParameters, trsp.QueuedLeaf.Leaf.LeafValue)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed creating signed debug info: %v", err)
	}
	rsp, err := sdi.MarshalB64()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	lastSdiTimestamp.Set(float64(time.Now().Unix()), i.LogParameters.id())
	if err := WriteJsonResponse(rsp, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getEntries provides a list of entries from the Trillian backend
func getEntries(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-entries request")
	req, err := NewGetEntriesRequest(i.LogParameters, r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	treq := trillian.GetLeavesByRangeRequest{
		LogId:      i.LogParameters.TreeId,
		StartIndex: req.Start,
		Count:      req.End - req.Start + 1,
	}
	trsp, err := i.Client.GetLeavesByRange(ctx, &treq)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("backend GetLeavesByRange request failed: %v", err)
	}
	if status, err := checkGetLeavesByRange(trsp, &req); err != nil {
		return status, err
	}

	rsp, err := NewGetEntriesResponse(trsp.Leaves)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed creating GetEntriesResponse: %v", err)
	}
	if err := WriteJsonResponse(rsp, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getAnchors provides a list of configured trust anchors
func getAnchors(_ context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-anchors request")
	data := NewGetAnchorsResponse(i.LogParameters.AnchorList)
	if err := WriteJsonResponse(data, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getProofByHash provides an inclusion proof based on a given leaf hash
func getProofByHash(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-proof-by-hash request")
	req, err := NewGetProofByHashRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	treq := trillian.GetInclusionProofByHashRequest{
		LogId:           i.LogParameters.TreeId,
		LeafHash:        req.Hash,
		TreeSize:        req.TreeSize,
		OrderBySequence: true,
	}
	trsp, err := i.Client.GetInclusionProofByHash(ctx, &treq)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed fetching inclusion proof from Trillian backend: %v", err)
	}
	if status, err := checkGetInclusionProofByHash(trsp, i.LogParameters); err != nil {
		return status, err
	}

	rsp, err := NewInclusionProofV1(i.LogParameters.LogId, uint64(req.TreeSize), trsp.Proof[0]).MarshalB64()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := WriteJsonResponse(rsp, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getConsistencyProof provides a consistency proof between two STHs
func getConsistencyProof(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-consistency-proof request")
	req, err := NewGetConsistencyProofRequest(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	treq := trillian.GetConsistencyProofRequest{
		LogId:          i.LogParameters.TreeId,
		FirstTreeSize:  int64(req.First),
		SecondTreeSize: int64(req.Second),
	}
	trsp, err := i.Client.GetConsistencyProof(ctx, &treq)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed fetching consistency proof from Trillian backend: %v", err)
	}
	if status, err := checkGetConsistencyProofResponse(trsp, i.LogParameters); err != nil {
		return status, err
	}

	rsp, err := NewConsistencyProofV1(i.LogParameters.LogId, req.First, req.Second, trsp.Proof).MarshalB64()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := WriteJsonResponse(rsp, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// getSth provides the most recent STH
func getSth(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-sth request")
	treq := trillian.GetLatestSignedLogRootRequest{
		LogId: i.LogParameters.TreeId,
	}
	trsp, err := i.Client.GetLatestSignedLogRoot(ctx, &treq)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed fetching signed tree head from Trillian backend: %v", err)
	}
	if status, err := checkTrillianGetLatestSignedLogRoot(trsp, i.LogParameters); err != nil {
		return status, err
	}

	th, err := NewTreeHeadV1(i.LogParameters, trsp.SignedLogRoot)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed creating tree head: %v", err)
	}
	sth, err := GenV1STH(i.LogParameters, th)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed creating signed tree head: %v", err)
	}
	rsp, err := sth.MarshalB64()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	lastSthTimestamp.Set(float64(time.Now().Unix()), i.LogParameters.id())
	lastSthSize.Set(float64(sth.SignedTreeHeadV1.TreeHead.TreeSize), i.LogParameters.id())
	if err := WriteJsonResponse(rsp, w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}
