package stfe

import (
	"context"
	"fmt"

	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/tls"
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
	var request AddEntryRequest
	if err := unpackRequest(r, &request); err != nil {
		return http.StatusBadRequest, err
	}

	item, err := verifyAddEntryRequest(request)
	if err != nil {
		return http.StatusBadRequest, err
	}
	glog.Infof("got item: %s", item)

	serializedItem, err := tls.Marshal(*item)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("tls marshal failed: %v", err)
	}
	trillianRequest := trillian.QueueLeafRequest{
		LogId: i.logID,
		Leaf: &trillian.LogLeaf{
			LeafValue: serializedItem,
			//TODO: add appendix here w/ chain + signature
		},
	}

	trillianResponse, err := i.client.QueueLeaf(ctx, &trillianRequest)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("backend QueueLeaf request failed: %v", err)
	}
	if trillianResponse == nil {
		return http.StatusInternalServerError, fmt.Errorf("missing QueueLeaf response")
	}
	// TODO: check that we got gRPC OK as specified in Trillian's API doc

	queuedLeaf := trillianResponse.QueuedLeaf
	glog.Infof("Queued leaf: %v", queuedLeaf.Leaf.LeafValue)
	// TODO: respond with an SDI

	return http.StatusOK, nil
}

// verifyAddEntryRequest
func verifyAddEntryRequest(r AddEntryRequest) (*StItem, error) {
	item, err := StItemFromB64(r.Item)
	if err != nil {
		return nil, fmt.Errorf("failed decoding StItem: %v", err)
	}
	if item.Format != StFormatChecksumV1 {
		return nil, fmt.Errorf("invalid StItem format: %s", item.Format)
	}
	// TODO: verify checksum length
	// TODO: verify r.Signature and r.Certificate
	return item, nil
}

// unpackRequest tries to unpack a json-encoded HTTP POST request into `unpack`
func unpackRequest(r *http.Request, unpack interface{}) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed reading request body: %v", err)
	}
	if err := json.Unmarshal(body, &unpack); err != nil {
		return fmt.Errorf("failed parsing json body: %v", err)
	}
	return nil
}

// getEntries provides with a list of entries from the Trillian backend
func getEntries(ctx context.Context, i *instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in getEntries")
	return http.StatusOK, nil // TODO
}

// getAnchors provides a list of configured trust anchors
func getAnchors(ctx context.Context, i *instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in getAnchors")
	return http.StatusOK, nil // TODO
}

// getProofByHash provides an inclusion proof based on a given leaf hash
func getProofByHash(ctx context.Context, i *instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in getProofByHash")
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
