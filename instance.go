package stfe

import (
	"context"
	"fmt"
	"time"

	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
)

// Instance is an instance of the system transparency front-end
type Instance struct {
	Client        trillian.TrillianLogClient
	LogParameters *LogParameters
	SthSource     SthSource
}

// Handlers returns a list of STFE handlers
func (i *Instance) Handlers() []Handler {
	return []Handler{
		Handler{Instance: i, Handler: addEntry, Endpoint: EndpointAddEntry, Method: http.MethodPost},
		Handler{Instance: i, Handler: addCosignature, Endpoint: EndpointAddCosignature, Method: http.MethodPost},
		Handler{Instance: i, Handler: getLatestSth, Endpoint: EndpointGetLatestSth, Method: http.MethodGet},
		Handler{Instance: i, Handler: getStableSth, Endpoint: EndpointGetStableSth, Method: http.MethodGet},
		Handler{Instance: i, Handler: getCosignedSth, Endpoint: EndpointGetCosignedSth, Method: http.MethodGet},
		Handler{Instance: i, Handler: getProofByHash, Endpoint: EndpointGetProofByHash, Method: http.MethodPost},
		Handler{Instance: i, Handler: getConsistencyProof, Endpoint: EndpointGetConsistencyProof, Method: http.MethodPost},
		Handler{Instance: i, Handler: getEntries, Endpoint: EndpointGetEntries, Method: http.MethodPost},
	}
}

// Handler implements the http.Handler interface, and contains a reference
// to an STFE server instance as well as a function that uses it.
type Handler struct {
	Instance *Instance
	Endpoint Endpoint
	Method   string
	Handler  func(context.Context, *Instance, http.ResponseWriter, *http.Request) (int, error)
}

// Path returns a path that should be configured for this handler
func (h Handler) Path() string {
	return h.Endpoint.Path("", h.Instance.LogParameters.Prefix)
}

// ServeHTTP is part of the http.Handler interface
func (a Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// export prometheus metrics
	var now time.Time = time.Now()
	var statusCode int
	defer func() {
		rspcnt.Inc(a.Instance.LogParameters.LogIdStr, string(a.Endpoint), fmt.Sprintf("%d", statusCode))
		latency.Observe(time.Now().Sub(now).Seconds(), a.Instance.LogParameters.LogIdStr, string(a.Endpoint), fmt.Sprintf("%d", statusCode))
	}()
	reqcnt.Inc(a.Instance.LogParameters.LogIdStr, string(a.Endpoint))

	ctx, cancel := context.WithDeadline(r.Context(), now.Add(a.Instance.LogParameters.Deadline))
	defer cancel()

	if r.Method != a.Method {
		glog.Warningf("%s/%s: got HTTP %s, wanted HTTP %s", a.Instance.LogParameters.Prefix, string(a.Endpoint), r.Method, a.Method)
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	statusCode, err := a.Handler(ctx, a.Instance, w, r)
	if err != nil {
		glog.Warningf("handler error %s/%s: %v", a.Instance.LogParameters.Prefix, a.Endpoint, err)
		http.Error(w, "", statusCode)
	}
}
