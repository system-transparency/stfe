package stfe

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"

	"net/http"
	"net/http/httptest"

	"github.com/golang/mock/gomock"
	cttestdata "github.com/google/certificate-transparency-go/trillian/testdata"
	"github.com/google/trillian"
	"github.com/system-transparency/stfe/testdata"
	"github.com/system-transparency/stfe/types"
)

func TestEndpointAddEntry(t *testing.T) {
	for _, table := range []struct {
		description string
		breq        *bytes.Buffer
		trsp        *trillian.QueueLeafResponse
		terr        error
		wantCode    int
	}{
		{
			description: "invalid: bad request: empty",
			breq:        bytes.NewBuffer(nil),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad Trillian response: error",
			breq:        testdata.AddSignedChecksumBuffer(t, testdata.Ed25519SkSubmitter, testdata.Ed25519VkSubmitter),
			terr:        fmt.Errorf("backend failure"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			breq:        testdata.AddSignedChecksumBuffer(t, testdata.Ed25519SkSubmitter, testdata.Ed25519VkSubmitter),
			trsp:        testdata.DefaultTQlr(t, false),
			wantCode:    http.StatusOK,
		},
	} {
		func() { // run deferred functions at the end of each iteration
			ti := newTestInstance(t, nil)
			defer ti.ctrl.Finish()

			url := EndpointAddEntry.Path("http://example.com", ti.instance.LogParameters.Prefix)
			req, err := http.NewRequest("POST", url, table.breq)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			if table.trsp != nil || table.terr != nil {
				ti.client.EXPECT().QueueLeaf(newDeadlineMatcher(), gomock.Any()).Return(table.trsp, table.terr) // TODO: deadline matcher?
			}

			w := httptest.NewRecorder()
			ti.postHandler(t, EndpointAddEntry).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got error code %d but wanted %d in test %q", got, want, table.description)
			}
		}()
	}
}

func TestEndpointAddCosignature(t *testing.T) {
	for _, table := range []struct {
		description string
		breq        *bytes.Buffer
		wantCode    int
	}{
		{
			description: "invalid: bad request: empty",
			breq:        bytes.NewBuffer(nil),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: signed wrong sth", // newLogParameters() use testdata.Ed25519VkLog as default
			breq:        testdata.AddCosignatureBuffer(t, testdata.DefaultSth(t, testdata.Ed25519VkLog2), &testdata.Ed25519SkWitness, &testdata.Ed25519VkWitness),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "valid",
			breq:        testdata.AddCosignatureBuffer(t, testdata.DefaultSth(t, testdata.Ed25519VkLog), &testdata.Ed25519SkWitness, &testdata.Ed25519VkWitness),
			wantCode:    http.StatusOK,
		},
	} {
		func() { // run deferred functions at the end of each iteration
			ti := newTestInstance(t, nil)
			defer ti.ctrl.Finish()

			url := EndpointAddCosignature.Path("http://example.com", ti.instance.LogParameters.Prefix)
			req, err := http.NewRequest("POST", url, table.breq)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}
			req.Header.Set("Content-Type", "application/octet-stream")

			w := httptest.NewRecorder()
			ti.postHandler(t, EndpointAddCosignature).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got error code %d but wanted %d in test %q", got, want, table.description)
			}
		}()
	}
}

func TestEndpointGetLatestSth(t *testing.T) {
	for _, table := range []struct {
		description string
		trsp        *trillian.GetLatestSignedLogRootResponse
		terr        error
		wantCode    int
		wantItem    *types.StItem
	}{
		{
			description: "backend failure",
			terr:        fmt.Errorf("backend failure"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			trsp:        testdata.DefaultTSlr(t),
			wantCode:    http.StatusOK,
			wantItem:    testdata.DefaultSth(t, testdata.Ed25519VkLog),
		},
	} {
		func() { // run deferred functions at the end of each iteration
			ti := newTestInstance(t, cttestdata.NewSignerWithFixedSig(nil, testdata.Signature))
			ti.ctrl.Finish()

			// Setup and run client query
			url := EndpointGetLatestSth.Path("http://example.com", ti.instance.LogParameters.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}
			if table.trsp != nil || table.terr != nil {
				ti.client.EXPECT().GetLatestSignedLogRoot(newDeadlineMatcher(), gomock.Any()).Return(table.trsp, table.terr) // TODO: deadline matcher?
			}

			w := httptest.NewRecorder()
			ti.getHandler(t, EndpointGetLatestSth).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got error code %d but wanted %d in test %q", got, want, table.description)
			}
			if w.Code != http.StatusOK {
				return
			}

			var item types.StItem
			if err := types.Unmarshal([]byte(w.Body.String()), &item); err != nil {
				t.Errorf("valid response cannot be unmarshalled in test %q: %v", table.description, err)
			}
			if got, want := item, *table.wantItem; !reflect.DeepEqual(got, want) {
				t.Errorf("got item\n%v\n\tbut wanted\n%v\n\tin test %q", got, want, table.description)
			}
		}()
	}
}

func TestEndpointGetStableSth(t *testing.T) {
	for _, table := range []struct {
		description  string
		useBadSource bool
		wantCode     int
		wantItem     *types.StItem
	}{
		{
			description:  "invalid: sth source failure",
			useBadSource: true,
			wantCode:     http.StatusInternalServerError,
		},
		{
			description: "valid",
			wantCode:    http.StatusOK,
			wantItem:    testdata.DefaultSth(t, testdata.Ed25519VkLog),
		},
	} {
		func() { // run deferred functions at the end of each iteration
			ti := newTestInstance(t, nil)
			ti.ctrl.Finish()
			if table.useBadSource {
				ti.instance.SthSource = &ActiveSthSource{}
			}

			// Setup and run client query
			url := EndpointGetStableSth.Path("http://example.com", ti.instance.LogParameters.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			w := httptest.NewRecorder()
			ti.getHandler(t, EndpointGetStableSth).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got error code %d but wanted %d in test %q", got, want, table.description)
			}
			if w.Code != http.StatusOK {
				return
			}

			var item types.StItem
			if err := types.Unmarshal([]byte(w.Body.String()), &item); err != nil {
				t.Errorf("valid response cannot be unmarshalled in test %q: %v", table.description, err)
			}
			if got, want := item, *table.wantItem; !reflect.DeepEqual(got, want) {
				t.Errorf("got item\n%v\n\tbut wanted\n%v\n\tin test %q", got, want, table.description)
			}
		}()
	}
}

func TestEndpointGetCosignedSth(t *testing.T) {
	for _, table := range []struct {
		description  string
		useBadSource bool
		wantCode     int
		wantItem     *types.StItem
	}{
		{
			description:  "invalid: sth source failure",
			useBadSource: true,
			wantCode:     http.StatusInternalServerError,
		},
		{
			description: "valid",
			wantCode:    http.StatusOK,
			wantItem:    testdata.DefaultCosth(t, testdata.Ed25519VkLog, [][32]byte{testdata.Ed25519VkWitness}),
		},
	} {
		func() { // run deferred functions at the end of each iteration
			ti := newTestInstance(t, nil)
			ti.ctrl.Finish()
			if table.useBadSource {
				ti.instance.SthSource = &ActiveSthSource{}
			}

			// Setup and run client query
			url := EndpointGetCosignedSth.Path("http://example.com", ti.instance.LogParameters.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			w := httptest.NewRecorder()
			ti.getHandler(t, EndpointGetCosignedSth).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got error code %d but wanted %d in test %q", got, want, table.description)
			}
			if w.Code != http.StatusOK {
				return
			}

			var item types.StItem
			if err := types.Unmarshal([]byte(w.Body.String()), &item); err != nil {
				t.Errorf("valid response cannot be unmarshalled in test %q: %v", table.description, err)
			}
			if got, want := item, *table.wantItem; !reflect.DeepEqual(got, want) {
				t.Errorf("got item\n%v\n\tbut wanted\n%v\n\tin test %q", got, want, table.description)
			}
		}()
	}
}

func TestEndpointGetProofByHash(t *testing.T) {
	for _, table := range []struct {
		description string
		breq        *bytes.Buffer
		trsp        *trillian.GetInclusionProofByHashResponse
		terr        error
		wantCode    int
		wantItem    *types.StItem
	}{
		{
			description: "invalid: bad request: empty",
			breq:        bytes.NewBuffer(nil),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad Trillian response: error",
			breq:        bytes.NewBuffer(marshal(t, types.GetProofByHashV1{TreeSize: 1, Hash: testdata.LeafHash})),
			terr:        fmt.Errorf("backend failure"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			breq:        bytes.NewBuffer(marshal(t, types.GetProofByHashV1{TreeSize: 1, Hash: testdata.LeafHash})),
			trsp:        testdata.DefaultTGipbhr(t),
			wantCode:    http.StatusOK,
			wantItem:    testdata.DefaultInclusionProof(t, 1),
		},
	} {
		func() { // run deferred functions at the end of each iteration
			ti := newTestInstance(t, nil)
			defer ti.ctrl.Finish()

			url := EndpointGetProofByHash.Path("http://example.com", ti.instance.LogParameters.Prefix)
			req, err := http.NewRequest("POST", url, table.breq)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			if table.trsp != nil || table.terr != nil {
				ti.client.EXPECT().GetInclusionProofByHash(newDeadlineMatcher(), gomock.Any()).Return(table.trsp, table.terr) // TODO: deadline matcher?
			}

			w := httptest.NewRecorder()
			ti.postHandler(t, EndpointGetProofByHash).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got error code %d but wanted %d in test %q", got, want, table.description)
			}
			if w.Code != http.StatusOK {
				return
			}

			var item types.StItem
			if err := types.Unmarshal([]byte(w.Body.String()), &item); err != nil {
				t.Errorf("valid response cannot be unmarshalled in test %q: %v", table.description, err)
			}
			if got, want := item, *table.wantItem; !reflect.DeepEqual(got, want) {
				t.Errorf("got item\n%v\n\tbut wanted\n%v\n\tin test %q", got, want, table.description)
			}
		}()
	}
}

func TestEndpointGetConsistencyProof(t *testing.T) {
	for _, table := range []struct {
		description string
		breq        *bytes.Buffer
		trsp        *trillian.GetConsistencyProofResponse
		terr        error
		wantCode    int
		wantItem    *types.StItem
	}{
		{
			description: "invalid: bad request: empty",
			breq:        bytes.NewBuffer(nil),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad Trillian response: error",
			breq:        bytes.NewBuffer(marshal(t, types.GetConsistencyProofV1{First: 1, Second: 2})),
			terr:        fmt.Errorf("backend failure"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			breq:        bytes.NewBuffer(marshal(t, types.GetConsistencyProofV1{First: 1, Second: 2})),
			trsp:        testdata.DefaultTGcpr(t),
			wantCode:    http.StatusOK,
			wantItem:    testdata.DefaultConsistencyProof(t, 1, 2),
		},
	} {
		func() { // run deferred functions at the end of each iteration
			ti := newTestInstance(t, nil)
			defer ti.ctrl.Finish()

			url := EndpointGetConsistencyProof.Path("http://example.com", ti.instance.LogParameters.Prefix)
			req, err := http.NewRequest("POST", url, table.breq)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			if table.trsp != nil || table.terr != nil {
				ti.client.EXPECT().GetConsistencyProof(newDeadlineMatcher(), gomock.Any()).Return(table.trsp, table.terr) // TODO: deadline matcher?
			}

			w := httptest.NewRecorder()
			ti.postHandler(t, EndpointGetConsistencyProof).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got error code %d but wanted %d in test %q", got, want, table.description)
			}
			if w.Code != http.StatusOK {
				return
			}

			var item types.StItem
			if err := types.Unmarshal([]byte(w.Body.String()), &item); err != nil {
				t.Errorf("valid response cannot be unmarshalled in test %q: %v", table.description, err)
			}
			if got, want := item, *table.wantItem; !reflect.DeepEqual(got, want) {
				t.Errorf("got item\n%v\n\tbut wanted\n%v\n\tin test %q", got, want, table.description)
			}
		}()
	}
}

func TestEndpointGetEntriesV1(t *testing.T) {
	for _, table := range []struct {
		description string
		breq        *bytes.Buffer
		trsp        *trillian.GetLeavesByRangeResponse
		terr        error
		wantCode    int
		wantItem    *types.StItemList
	}{
		{
			description: "invalid: bad request: empty",
			breq:        bytes.NewBuffer(nil),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad Trillian response: error",
			breq:        bytes.NewBuffer(marshal(t, types.GetEntriesV1{Start: 0, End: 0})),
			terr:        fmt.Errorf("backend failure"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid", // remember that newLogParameters() have testdata.MaxRange configured
			breq:        bytes.NewBuffer(marshal(t, types.GetEntriesV1{Start: 0, End: uint64(testdata.MaxRange - 1)})),
			trsp:        testdata.DefaultTGlbrr(t, 0, testdata.MaxRange-1),
			wantCode:    http.StatusOK,
			wantItem:    testdata.DefaultStItemList(t, 0, uint64(testdata.MaxRange)-1),
		},
	} {
		func() { // run deferred functions at the end of each iteration
			ti := newTestInstance(t, nil)
			defer ti.ctrl.Finish()

			url := EndpointGetEntries.Path("http://example.com", ti.instance.LogParameters.Prefix)
			req, err := http.NewRequest("POST", url, table.breq)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			if table.trsp != nil || table.terr != nil {
				ti.client.EXPECT().GetLeavesByRange(newDeadlineMatcher(), gomock.Any()).Return(table.trsp, table.terr) // TODO: deadline matcher?
			}

			w := httptest.NewRecorder()
			ti.postHandler(t, EndpointGetEntries).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got error code %d but wanted %d in test %q", got, want, table.description)
			}
			if w.Code != http.StatusOK {
				return
			}

			var item types.StItemList
			if err := types.Unmarshal([]byte(w.Body.String()), &item); err != nil {
				t.Errorf("valid response cannot be unmarshalled in test %q: %v", table.description, err)
			}
			if got, want := item, *table.wantItem; !reflect.DeepEqual(got, want) {
				t.Errorf("got item\n%v\n\tbut wanted\n%v\n\tin test %q", got, want, table.description)
			}
		}()
	}
}

func TestEndpointPath(t *testing.T) {
	base, prefix, proto := "http://example.com", "test", "st/v1"
	for _, table := range []struct {
		endpoint Endpoint
		want     string
	}{
		{
			endpoint: EndpointAddEntry,
			want:     "http://example.com/test/st/v1/add-entry",
		},
		{
			endpoint: EndpointAddCosignature,
			want:     "http://example.com/test/st/v1/add-cosignature",
		},
		{
			endpoint: EndpointGetLatestSth,
			want:     "http://example.com/test/st/v1/get-latest-sth",
		},
		{
			endpoint: EndpointGetStableSth,
			want:     "http://example.com/test/st/v1/get-stable-sth",
		},
		{
			endpoint: EndpointGetCosignedSth,
			want:     "http://example.com/test/st/v1/get-cosigned-sth",
		},
		{
			endpoint: EndpointGetConsistencyProof,
			want:     "http://example.com/test/st/v1/get-consistency-proof",
		},
		{
			endpoint: EndpointGetProofByHash,
			want:     "http://example.com/test/st/v1/get-proof-by-hash",
		},
		{
			endpoint: EndpointGetEntries,
			want:     "http://example.com/test/st/v1/get-entries",
		},
	} {
		if got, want := table.endpoint.Path(base+"/"+prefix+"/"+proto), table.want; got != want {
			t.Errorf("got endpoint\n%s\n\tbut wanted\n%s\n\twith one component", got, want)
		}
		if got, want := table.endpoint.Path(base, prefix, proto), table.want; got != want {
			t.Errorf("got endpoint\n%s\n\tbut wanted\n%s\n\tmultiple components", got, want)
		}
	}
}

// TODO: TestWriteOctetResponse
func TestWriteOctetResponse(t *testing.T) {
}

// deadlineMatcher implements gomock.Matcher, such that an error is raised if
// there is no context.Context deadline set
type deadlineMatcher struct{}

// newDeadlineMatcher returns a new DeadlineMatcher
func newDeadlineMatcher() gomock.Matcher {
	return &deadlineMatcher{}
}

// Matches returns true if the passed interface is a context with a deadline
func (dm *deadlineMatcher) Matches(i interface{}) bool {
	ctx, ok := i.(context.Context)
	if !ok {
		return false
	}
	_, ok = ctx.Deadline()
	return ok
}

// String is needed to implement gomock.Matcher
func (dm *deadlineMatcher) String() string {
	return fmt.Sprintf("deadlineMatcher{}")
}
