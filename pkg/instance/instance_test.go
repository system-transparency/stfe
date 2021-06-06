package stfe

import (
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/certificate-transparency-go/trillian/mockclient"
	"github.com/system-transparency/stfe/pkg/testdata"
	"github.com/system-transparency/stfe/pkg/types"
)

type testInstance struct {
	ctrl     *gomock.Controller
	client   *mockclient.MockTrillianLogClient
	instance *Instance
}

// newTestInstances sets up a test instance that uses default log parameters
// with an optional signer, see newLogParameters() for further details.  The
// SthSource is instantiated with an ActiveSthSource that has (i) the default
// STH as the currently cosigned STH based on testdata.Ed25519VkWitness, and
// (ii) the default STH without any cosignatures as the currently stable STH.
func newTestInstance(t *testing.T, signer crypto.Signer) *testInstance {
	t.Helper()
	ctrl := gomock.NewController(t)
	client := mockclient.NewMockTrillianLogClient(ctrl)
	return &testInstance{
		ctrl:   ctrl,
		client: client,
		instance: &Instance{
			Client:        client,
			LogParameters: newLogParameters(t, signer),
			SthSource: &ActiveSthSource{
				client:          client,
				logParameters:   newLogParameters(t, signer),
				currCosth:       testdata.DefaultCosth(t, testdata.Ed25519VkLog, [][32]byte{testdata.Ed25519VkWitness}),
				nextCosth:       testdata.DefaultCosth(t, testdata.Ed25519VkLog, nil),
				cosignatureFrom: make(map[[types.NamespaceFingerprintSize]byte]bool),
			},
		},
	}
}

// getHandlers returns all endpoints that use HTTP GET as a map to handlers
func (ti *testInstance) getHandlers(t *testing.T) map[Endpoint]Handler {
	t.Helper()
	return map[Endpoint]Handler{
		EndpointGetLatestSth:   Handler{Instance: ti.instance, Handler: getLatestSth, Endpoint: EndpointGetLatestSth, Method: http.MethodGet},
		EndpointGetStableSth:   Handler{Instance: ti.instance, Handler: getStableSth, Endpoint: EndpointGetStableSth, Method: http.MethodGet},
		EndpointGetCosignedSth: Handler{Instance: ti.instance, Handler: getCosignedSth, Endpoint: EndpointGetCosignedSth, Method: http.MethodGet},
	}
}

// postHandlers returns all endpoints that use HTTP POST as a map to handlers
func (ti *testInstance) postHandlers(t *testing.T) map[Endpoint]Handler {
	t.Helper()
	return map[Endpoint]Handler{
		EndpointAddEntry:            Handler{Instance: ti.instance, Handler: addEntry, Endpoint: EndpointAddEntry, Method: http.MethodPost},
		EndpointAddCosignature:      Handler{Instance: ti.instance, Handler: addCosignature, Endpoint: EndpointAddCosignature, Method: http.MethodPost},
		EndpointGetConsistencyProof: Handler{Instance: ti.instance, Handler: getConsistencyProof, Endpoint: EndpointGetConsistencyProof, Method: http.MethodPost},
		EndpointGetProofByHash:      Handler{Instance: ti.instance, Handler: getProofByHash, Endpoint: EndpointGetProofByHash, Method: http.MethodPost},
		EndpointGetEntries:          Handler{Instance: ti.instance, Handler: getEntries, Endpoint: EndpointGetEntries, Method: http.MethodPost},
	}
}

// getHandler must return a particular HTTP GET handler
func (ti *testInstance) getHandler(t *testing.T, endpoint Endpoint) Handler {
	t.Helper()
	handler, ok := ti.getHandlers(t)[endpoint]
	if !ok {
		t.Fatalf("must return HTTP GET handler for endpoint: %s", endpoint)
	}
	return handler
}

// postHandler must return a particular HTTP POST handler
func (ti *testInstance) postHandler(t *testing.T, endpoint Endpoint) Handler {
	t.Helper()
	handler, ok := ti.postHandlers(t)[endpoint]
	if !ok {
		t.Fatalf("must return HTTP POST handler for endpoint: %s", endpoint)
	}
	return handler
}

// TestHandlers checks that we configured all endpoints and that there are no
// unexpected ones.
func TestHandlers(t *testing.T) {
	endpoints := map[Endpoint]bool{
		EndpointAddEntry:            false,
		EndpointAddCosignature:      false,
		EndpointGetLatestSth:        false,
		EndpointGetStableSth:        false,
		EndpointGetCosignedSth:      false,
		EndpointGetConsistencyProof: false,
		EndpointGetProofByHash:      false,
		EndpointGetEntries:          false,
	}
	i := &Instance{nil, newLogParameters(t, nil), nil}
	for _, handler := range i.Handlers() {
		if _, ok := endpoints[handler.Endpoint]; !ok {
			t.Errorf("got unexpected endpoint: %s", handler.Endpoint)
		}
		endpoints[handler.Endpoint] = true
	}
	for endpoint, ok := range endpoints {
		if !ok {
			t.Errorf("endpoint %s is not configured", endpoint)
		}
	}
}

// TestGetHandlersRejectPost checks that all get handlers reject post requests
func TestGetHandlersRejectPost(t *testing.T) {
	ti := newTestInstance(t, nil)
	defer ti.ctrl.Finish()

	for endpoint, handler := range ti.getHandlers(t) {
		t.Run(string(endpoint), func(t *testing.T) {
			s := httptest.NewServer(handler)
			defer s.Close()

			url := endpoint.Path(s.URL, ti.instance.LogParameters.Prefix)
			if rsp, err := http.Post(url, "application/json", nil); err != nil {
				t.Fatalf("http.Post(%s)=(_,%q), want (_,nil)", url, err)
			} else if rsp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("http.Post(%s)=(%d,nil), want (%d, nil)", url, rsp.StatusCode, http.StatusMethodNotAllowed)
			}
		})
	}
}

// TestPostHandlersRejectGet checks that all post handlers reject get requests
func TestPostHandlersRejectGet(t *testing.T) {
	ti := newTestInstance(t, nil)
	defer ti.ctrl.Finish()

	for endpoint, handler := range ti.postHandlers(t) {
		t.Run(string(endpoint), func(t *testing.T) {
			s := httptest.NewServer(handler)
			defer s.Close()

			url := endpoint.Path(s.URL, ti.instance.LogParameters.Prefix)
			if rsp, err := http.Get(url); err != nil {
				t.Fatalf("http.Get(%s)=(_,%q), want (_,nil)", url, err)
			} else if rsp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("http.Get(%s)=(%d,nil), want (%d, nil)", url, rsp.StatusCode, http.StatusMethodNotAllowed)
			}
		})
	}
}

// TODO: TestHandlerPath
func TestHandlerPath(t *testing.T) {
}
