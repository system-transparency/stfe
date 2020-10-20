package stfe

import (
	"context"
	"fmt"

	"net/http"

	"github.com/golang/glog"
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
		glog.Warningf("handler error %s: %v", a.instance.prefix+a.endpoint, err)
		a.sendHTTPError(w, statusCode, err)
	}
}

// sendHTTPError replies to a request with an error message and a status code.
func (a appHandler) sendHTTPError(w http.ResponseWriter, statusCode int, err error) {
	http.Error(w, http.StatusText(statusCode), statusCode)
}

// addEntry adds an entry to the Trillian backend
func addEntry(ctx context.Context, i *instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.Info("in addEntry")
	return http.StatusOK, nil // TODO
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
