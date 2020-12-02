package stfe

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"testing"
	"time"

	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/golang/mock/gomock"
	"github.com/google/certificate-transparency-go/trillian/mockclient"
	cttestdata "github.com/google/certificate-transparency-go/trillian/testdata"
	"github.com/google/trillian"
	"github.com/system-transparency/stfe/x509util"
	"github.com/system-transparency/stfe/x509util/testdata"
)

var (
	testDeadline = time.Second * 10
)

type testHandler struct {
	mockCtrl *gomock.Controller
	client   *mockclient.MockTrillianLogClient
	instance *Instance
}

func newTestHandler(t *testing.T, signer crypto.Signer) *testHandler {
	ctrl := gomock.NewController(t)
	client := mockclient.NewMockTrillianLogClient(ctrl)
	return &testHandler{
		mockCtrl: ctrl,
		client:   client,
		instance: &Instance{
			Deadline:      testDeadline,
			Client:        client,
			LogParameters: makeTestLogParameters(t, signer),
		},
	}
}

func (th *testHandler) getHandlers(t *testing.T) map[Endpoint]Handler {
	return map[Endpoint]Handler{
		EndpointGetSth:              Handler{instance: th.instance, handler: getSth, endpoint: EndpointGetSth, method: http.MethodGet},
		EndpointGetConsistencyProof: Handler{instance: th.instance, handler: getConsistencyProof, endpoint: EndpointGetConsistencyProof, method: http.MethodGet},
		EndpointGetProofByHash:      Handler{instance: th.instance, handler: getProofByHash, endpoint: EndpointGetProofByHash, method: http.MethodGet},
		EndpointGetAnchors:          Handler{instance: th.instance, handler: getAnchors, endpoint: EndpointGetAnchors, method: http.MethodGet},
		EndpointGetEntries:          Handler{instance: th.instance, handler: getEntries, endpoint: EndpointGetEntries, method: http.MethodGet},
	}
}

func (th *testHandler) getHandler(t *testing.T, endpoint Endpoint) Handler {
	handler, ok := th.getHandlers(t)[endpoint]
	if !ok {
		t.Fatalf("no such get endpoint: %s", endpoint)
	}
	return handler
}

func (th *testHandler) postHandlers(t *testing.T) map[Endpoint]Handler {
	return map[Endpoint]Handler{
		EndpointAddEntry: Handler{instance: th.instance, handler: addEntry, endpoint: EndpointAddEntry, method: http.MethodPost},
	}
}

func (th *testHandler) postHandler(t *testing.T, endpoint Endpoint) Handler {
	handler, ok := th.postHandlers(t)[endpoint]
	if !ok {
		t.Fatalf("no such post endpoint: %s", endpoint)
	}
	return handler
}

// TestGetHandlersRejectPost checks that all get handlers reject post requests
func TestGetHandlersRejectPost(t *testing.T) {
	th := newTestHandler(t, nil)
	defer th.mockCtrl.Finish()

	for endpoint, handler := range th.getHandlers(t) {
		t.Run(string(endpoint), func(t *testing.T) {
			s := httptest.NewServer(handler)
			defer s.Close()

			url := endpoint.Path(s.URL, th.instance.LogParameters.Prefix)
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
	th := newTestHandler(t, nil)
	defer th.mockCtrl.Finish()

	for endpoint, handler := range th.postHandlers(t) {
		t.Run(string(endpoint), func(t *testing.T) {
			s := httptest.NewServer(handler)
			defer s.Close()

			url := endpoint.Path(s.URL, th.instance.LogParameters.Prefix)
			if rsp, err := http.Get(url); err != nil {
				t.Fatalf("http.Get(%s)=(_,%q), want (_,nil)", url, err)
			} else if rsp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("http.Get(%s)=(%d,nil), want (%d, nil)", url, rsp.StatusCode, http.StatusMethodNotAllowed)
			}
		})
	}
}

// TestGetAnchors checks for a valid number of decodable trust anchors
func TestGetAnchors(t *testing.T) {
	th := newTestHandler(t, nil)
	defer th.mockCtrl.Finish()

	url := EndpointGetAnchors.Path("http://example.com", th.instance.LogParameters.Prefix)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("failed creating http request: %v", err)
	}

	w := httptest.NewRecorder()
	th.getHandler(t, EndpointGetAnchors).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET(%s)=%d, want http status code %d", url, w.Code, http.StatusOK)
		return
	}

	var derAnchors [][]byte
	if err := json.Unmarshal([]byte(w.Body.String()), &derAnchors); err != nil {
		t.Errorf("failed unmarshaling trust anchors response: %v", err)
		return
	}
	if got, want := len(derAnchors), len(th.instance.LogParameters.AnchorList); got != want {
		t.Errorf("unexpected trust anchor count %d, want %d", got, want)
	}
	if _, err := x509util.ParseDerList(derAnchors); err != nil {
		t.Errorf("failed decoding trust anchors: %v", err)
	}
}

func TestGetEntries(t *testing.T) {
	chainLen := 3
	for _, table := range []struct {
		description string
		breq        *GetEntriesRequest
		trsp        *trillian.GetLeavesByRangeResponse
		terr        error
		wantCode    int
		wantErrText string
	}{
		{
			description: "bad request parameters",
			breq: &GetEntriesRequest{
				Start: 1,
				End:   0,
			},
			wantCode:    http.StatusBadRequest,
			wantErrText: http.StatusText(http.StatusBadRequest) + "\n",
		},
		{
			description: "empty trillian response",
			breq: &GetEntriesRequest{
				Start: 0,
				End:   1,
			},
			terr:        fmt.Errorf("back-end failure"),
			wantCode:    http.StatusInternalServerError,
			wantErrText: http.StatusText(http.StatusInternalServerError) + "\n",
		},
		{
			description: "invalid get-entries response",
			breq: &GetEntriesRequest{
				Start: 0,
				End:   1,
			},
			trsp:        makeTrillianGetLeavesByRangeResponse(t, 0, 1, []byte("foobar-1.2.3"), testdata.RootChain, testdata.EndEntityPrivateKey, false),
			wantCode:    http.StatusInternalServerError,
			wantErrText: http.StatusText(http.StatusInternalServerError) + "\n",
		},
		{
			description: "valid get-entries response",
			breq: &GetEntriesRequest{
				Start: 0,
				End:   1,
			},
			trsp:     makeTrillianGetLeavesByRangeResponse(t, 0, 1, []byte("foobar-1.2.3"), testdata.RootChain, testdata.EndEntityPrivateKey, true),
			wantCode: http.StatusOK,
		},
	} {
		func() { // run deferred functions at the end of each iteration
			th := newTestHandler(t, nil)
			defer th.mockCtrl.Finish()

			url := EndpointGetEntries.Path("http://example.com", th.instance.LogParameters.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("failed creating http request: %v", err)
			}
			q := req.URL.Query()
			q.Add("start", fmt.Sprintf("%d", table.breq.Start))
			q.Add("end", fmt.Sprintf("%d", table.breq.End))
			req.URL.RawQuery = q.Encode()

			if table.trsp != nil || table.terr != nil {
				th.client.EXPECT().GetLeavesByRange(newDeadlineMatcher(), gomock.Any()).Return(table.trsp, table.terr)
			}
			w := httptest.NewRecorder()
			th.getHandler(t, EndpointGetEntries).ServeHTTP(w, req)
			if w.Code != table.wantCode {
				t.Errorf("GET(%s)=%d, want http status code %d", url, w.Code, table.wantCode)
			}

			body := w.Body.String()
			if w.Code != http.StatusOK {
				if body != table.wantErrText {
					t.Errorf("GET(%s)=%q, want text %q", url, body, table.wantErrText)
				}
				return
			}

			var rsps []*GetEntryResponse
			if err := json.Unmarshal([]byte(body), &rsps); err != nil {
				t.Errorf("failed parsing list of log entries: %v", err)
				return
			}
			for i, rsp := range rsps {
				var item StItem
				if err := item.Unmarshal(rsp.Item); err != nil {
					t.Errorf("failed unmarshaling StItem: %v", err)
				} else {
					if item.Format != StFormatChecksumV1 {
						t.Errorf("invalid StFormat: got %v, want %v", item.Format, StFormatChecksumV1)
					}
					checksum := item.ChecksumV1
					if got, want := checksum.Package, []byte(fmt.Sprintf("%s_%d", "foobar-1.2.3", int64(i)+table.breq.Start)); !bytes.Equal(got, want) {
						t.Errorf("got package name %s, want %s", string(got), string(want))
					}
					if got, want := checksum.Checksum, make([]byte, 32); !bytes.Equal(got, want) {
						t.Errorf("got package checksum %X, want %X", got, want)
					}
				}

				chain, err := x509util.ParseDerList(rsp.Chain)
				if err != nil {
					t.Errorf("failed parsing certificate chain: %v", err)
				} else if got, want := len(chain), chainLen; got != want {
					t.Errorf("got chain length %d, want %d", got, want)
				} else {
					if err := x509util.VerifyChain(chain); err != nil {
						t.Errorf("invalid certificate chain: %v", err)
					}
				}
				if got, want := tls.SignatureScheme(rsp.SignatureScheme), tls.Ed25519; got != want {
					t.Errorf("got signature scheme %s, want %s", got, want)
				}
				if !ed25519.Verify(chain[0].PublicKey.(ed25519.PublicKey), rsp.Item, rsp.Signature) {
					t.Errorf("invalid ed25519 signature")
				}
			}
		}()
	}
}

func TestAddEntry(t *testing.T) {
	for _, table := range []struct {
		description string
		breq        *bytes.Buffer
		trsp        *trillian.QueueLeafResponse
		terr        error
		wantCode    int
		wantErrText string
		signer      crypto.Signer
	}{
		{
			description: "empty trillian response",
			breq:        makeTestLeafBuffer(t, []byte("foobar-1.2.3"), testdata.IntermediateChain, testdata.EndEntityPrivateKey, true),
			terr:        fmt.Errorf("back-end failure"),
			wantCode:    http.StatusInternalServerError,
			wantErrText: http.StatusText(http.StatusInternalServerError) + "\n",
		},
		{
			description: "bad request parameters",
			breq:        makeTestLeafBuffer(t, []byte("foobar-1.2.3"), testdata.IntermediateChain, testdata.EndEntityPrivateKey, false),
			wantCode:    http.StatusBadRequest,
			wantErrText: http.StatusText(http.StatusBadRequest) + "\n",
		},
		{
			description: "log signature failure",
			breq:        makeTestLeafBuffer(t, []byte("foobar-1.2.3"), testdata.IntermediateChain, testdata.EndEntityPrivateKey, true),
			trsp:        makeTrillianQueueLeafResponse(t, []byte("foobar-1.2.3"), testdata.IntermediateChain, testdata.EndEntityPrivateKey, false),
			wantCode:    http.StatusInternalServerError,
			wantErrText: http.StatusText(http.StatusInternalServerError) + "\n",
			signer:      cttestdata.NewSignerWithErr(nil, fmt.Errorf("signing failed")),
		},
		{
			description: "valid add-entry request-response",
			breq:        makeTestLeafBuffer(t, []byte("foobar-1.2.3"), testdata.IntermediateChain, testdata.EndEntityPrivateKey, true),
			trsp:        makeTrillianQueueLeafResponse(t, []byte("foobar-1.2.3"), testdata.IntermediateChain, testdata.EndEntityPrivateKey, false),
			wantCode:    http.StatusOK,
			signer:      cttestdata.NewSignerWithFixedSig(nil, make([]byte, 32)),
		},
	} {
		func() { // run deferred functions at the end of each iteration
			th := newTestHandler(t, table.signer)
			defer th.mockCtrl.Finish()

			url := EndpointAddEntry.Path("http://example.com", th.instance.LogParameters.Prefix)
			req, err := http.NewRequest("POST", url, table.breq)
			if err != nil {
				t.Fatalf("failed creating http request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			if table.trsp != nil || table.terr != nil {
				th.client.EXPECT().QueueLeaf(newDeadlineMatcher(), gomock.Any()).Return(table.trsp, table.terr)
			}
			w := httptest.NewRecorder()
			th.postHandler(t, EndpointAddEntry).ServeHTTP(w, req)
			if w.Code != table.wantCode {
				t.Errorf("GET(%s)=%d, want http status code %d", url, w.Code, table.wantCode)
			}

			body := w.Body.String()
			if w.Code != http.StatusOK {
				if body != table.wantErrText {
					t.Errorf("GET(%s)=%q, want text %q", url, body, table.wantErrText)
				}
				return
			}

			// status code is http.StatusOK, check response
			var data []byte
			if err := json.Unmarshal([]byte(body), &data); err != nil {
				t.Errorf("failed unmarshaling json: %v, wanted ok", err)
				return
			}
			var item StItem
			if err := item.Unmarshal(data); err != nil {
				t.Errorf("failed unmarshaling StItem: %v, wanted ok", err)
				return
			}
			if item.Format != StFormatSignedDebugInfoV1 {
				t.Errorf("invalid StFormat: got %v, want %v", item.Format, StFormatSignedDebugInfoV1)
			}
			sdi := item.SignedDebugInfoV1
			if !bytes.Equal(sdi.LogId, th.instance.LogParameters.LogId) {
				t.Errorf("want log id %X, got %X", sdi.LogId, th.instance.LogParameters.LogId)
			}
			if len(sdi.Message) == 0 {
				t.Errorf("expected message, got none")
			}
			if !bytes.Equal(sdi.Signature, make([]byte, 32)) {
				t.Errorf("want signature %X, got %X", sdi.Signature, make([]byte, 32))
			}
		}()
	}
}

func TestGetSth(t *testing.T) {
	tr := makeLatestSignedLogRootResponse(t, 0, 0, make([]byte, 32))
	tr.SignedLogRoot.LogRoot = tr.SignedLogRoot.LogRoot[1:]
	for _, table := range []struct {
		description string
		trsp        *trillian.GetLatestSignedLogRootResponse
		terr        error
		wantCode    int
		wantErrText string
		signer      crypto.Signer
	}{
		{
			description: "empty trillian response",
			terr:        fmt.Errorf("back-end failure"),
			wantCode:    http.StatusInternalServerError,
			wantErrText: http.StatusText(http.StatusInternalServerError) + "\n",
		},
		{
			description: "marshal failure: no signature",
			trsp:        makeLatestSignedLogRootResponse(t, 0, 0, make([]byte, 32)),
			wantCode:    http.StatusInternalServerError,
			wantErrText: http.StatusText(http.StatusInternalServerError) + "\n",
			signer:      cttestdata.NewSignerWithFixedSig(nil, make([]byte, 0)),
		},
		{
			description: "signature failure",
			trsp:        makeLatestSignedLogRootResponse(t, 0, 0, make([]byte, 32)),
			wantCode:    http.StatusInternalServerError,
			wantErrText: http.StatusText(http.StatusInternalServerError) + "\n",
			signer:      cttestdata.NewSignerWithErr(nil, fmt.Errorf("signing failed")),
		},
		{
			description: "valid request and response",
			trsp:        makeLatestSignedLogRootResponse(t, 0, 0, make([]byte, 32)),
			wantCode:    http.StatusOK,
			signer:      cttestdata.NewSignerWithFixedSig(nil, make([]byte, 32)),
		},
	} {
		func() { // run deferred functions at the end of each iteration
			th := newTestHandler(t, table.signer)
			defer th.mockCtrl.Finish()

			url := EndpointGetSth.Path("http://example.com", th.instance.LogParameters.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("failed creating http request: %v", err)
			}

			w := httptest.NewRecorder()
			th.client.EXPECT().GetLatestSignedLogRoot(newDeadlineMatcher(), gomock.Any()).Return(table.trsp, table.terr)
			th.getHandler(t, EndpointGetSth).ServeHTTP(w, req)
			if w.Code != table.wantCode {
				t.Errorf("GET(%s)=%d, want http status code %d", url, w.Code, table.wantCode)
			}

			body := w.Body.String()
			if w.Code != http.StatusOK {
				if body != table.wantErrText {
					t.Errorf("GET(%s)=%q, want text %q", url, body, table.wantErrText)
				}
				return
			}

			// status code is http.StatusOK, check response
			var data []byte
			if err := json.Unmarshal([]byte(body), &data); err != nil {
				t.Errorf("failed unmarshaling json: %v, wanted ok", err)
				return
			}
			var item StItem
			if err := item.Unmarshal(data); err != nil {
				t.Errorf("failed unmarshaling StItem: %v, wanted ok", err)
				return
			}
			if item.Format != StFormatSignedTreeHeadV1 {
				t.Errorf("invalid StFormat: got %v, want %v", item.Format, StFormatSignedTreeHeadV1)
			}
			sth := item.SignedTreeHeadV1
			if !bytes.Equal(sth.LogId, th.instance.LogParameters.LogId) {
				t.Errorf("want log id %X, got %X", sth.LogId, th.instance.LogParameters.LogId)
			}
			if !bytes.Equal(sth.Signature, make([]byte, 32)) {
				t.Errorf("want signature %X, got %X", sth.Signature, make([]byte, 32))
			}
			if sth.TreeHead.TreeSize != 0 {
				t.Errorf("want tree size %d, got %d", 0, sth.TreeHead.TreeSize)
			}
			if sth.TreeHead.Timestamp != 0 {
				t.Errorf("want timestamp %d, got %d", 0, sth.TreeHead.Timestamp)
			}
			if !bytes.Equal(sth.TreeHead.RootHash.Data, make([]byte, 32)) {
				t.Errorf("want root hash %X, got %X", make([]byte, 32), sth.TreeHead.RootHash)
			}
			if len(sth.TreeHead.Extension) != 0 {
				t.Errorf("want no extensions, got %v", sth.TreeHead.Extension)
			}
		}()
	}
}

func TestGetConsistencyProof(t *testing.T) {
	fixedProof := [][]byte{
		make([]byte, 32),
		make([]byte, 32),
	}
	for _, table := range []struct {
		description string
		breq        *GetConsistencyProofRequest
		trsp        *trillian.GetConsistencyProofResponse
		terr        error
		wantCode    int
		wantErrText string
	}{
		{
			description: "bad request parameters",
			breq: &GetConsistencyProofRequest{
				First:  2,
				Second: 1,
			},
			wantCode:    http.StatusBadRequest,
			wantErrText: http.StatusText(http.StatusBadRequest) + "\n",
		},
		{
			description: "empty trillian response",
			breq: &GetConsistencyProofRequest{
				First:  1,
				Second: 2,
			},
			terr:        fmt.Errorf("back-end failure"),
			wantCode:    http.StatusInternalServerError,
			wantErrText: http.StatusText(http.StatusInternalServerError) + "\n",
		},
		{
			description: "valid request and response",
			breq: &GetConsistencyProofRequest{
				First:  1,
				Second: 2,
			},
			trsp:     makeTrillianGetConsistencyProofResponse(t, fixedProof),
			wantCode: http.StatusOK,
		},
	} {
		func() { // run deferred functions at the end of each iteration
			th := newTestHandler(t, nil)
			defer th.mockCtrl.Finish()

			url := EndpointGetConsistencyProof.Path("http://example.com", th.instance.LogParameters.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("failed creating http request: %v", err)
			}
			q := req.URL.Query()
			q.Add("first", fmt.Sprintf("%d", table.breq.First))
			q.Add("second", fmt.Sprintf("%d", table.breq.Second))
			req.URL.RawQuery = q.Encode()

			w := httptest.NewRecorder()
			if table.trsp != nil || table.terr != nil {
				th.client.EXPECT().GetConsistencyProof(newDeadlineMatcher(), gomock.Any()).Return(table.trsp, table.terr)
			}
			th.getHandler(t, EndpointGetConsistencyProof).ServeHTTP(w, req)
			if w.Code != table.wantCode {
				t.Errorf("GET(%s)=%d, want http status code %d", url, w.Code, table.wantCode)
			}
			body := w.Body.String()
			if w.Code != http.StatusOK {
				if body != table.wantErrText {
					t.Errorf("GET(%s)=%q, want text %q", url, body, table.wantErrText)
				}
				return
			}

			// status code is http.StatusOK, check response
			var data []byte
			if err := json.Unmarshal([]byte(body), &data); err != nil {
				t.Errorf("failed unmarshaling json: %v, wanted ok", err)
				return
			}
			var item StItem
			if err := item.Unmarshal(data); err != nil {
				t.Errorf("failed unmarshaling StItem: %v, wanted ok", err)
				return
			}
			if item.Format != StFormatConsistencyProofV1 {
				t.Errorf("invalid StFormat: got %v, want %v", item.Format, StFormatInclusionProofV1)
			}
			proof := item.ConsistencyProofV1
			if !bytes.Equal(proof.LogId, th.instance.LogParameters.LogId) {
				t.Errorf("want log id %X, got %X", proof.LogId, th.instance.LogParameters.LogId)
			}
			if got, want := proof.TreeSize1, uint64(table.breq.First); got != want {
				t.Errorf("want tree size %d, got %d", want, got)
			}
			if got, want := proof.TreeSize2, uint64(table.breq.Second); got != want {
				t.Errorf("want tree size %d, got %d", want, got)
			}
			if got, want := len(proof.ConsistencyPath), len(fixedProof); got != want {
				t.Errorf("want proof length %d, got %d", want, got)
				return
			}
			for i, nh := range proof.ConsistencyPath {
				if !bytes.Equal(nh.Data, fixedProof[i]) {
					t.Errorf("want proof[%d]=%X, got %X", i, fixedProof[i], nh.Data)
				}
			}
		}()
	}
}

func TestGetProofByHash(t *testing.T) {
	fixedProof := [][]byte{
		make([]byte, 32),
		make([]byte, 32),
	}
	for _, table := range []struct {
		description string
		breq        *GetProofByHashRequest
		trsp        *trillian.GetInclusionProofByHashResponse
		terr        error
		wantCode    int
		wantErrText string
	}{
		{
			description: "bad request parameters",
			breq: &GetProofByHashRequest{
				Hash:     make([]byte, 32),
				TreeSize: 0,
			},
			wantCode:    http.StatusBadRequest,
			wantErrText: http.StatusText(http.StatusBadRequest) + "\n",
		},
		{
			description: "empty trillian response",
			breq: &GetProofByHashRequest{
				Hash:     make([]byte, 32),
				TreeSize: 128,
			},
			terr:        fmt.Errorf("back-end failure"),
			wantCode:    http.StatusInternalServerError,
			wantErrText: http.StatusText(http.StatusInternalServerError) + "\n",
		},
		{
			description: "valid request and response",
			breq: &GetProofByHashRequest{
				Hash:     make([]byte, 32),
				TreeSize: 128,
			},
			trsp:     makeTrillianGetInclusionProofByHashResponse(t, 0, fixedProof),
			wantCode: http.StatusOK,
		},
	} {
		func() { // run deferred functions at the end of each iteration
			th := newTestHandler(t, nil)
			defer th.mockCtrl.Finish()

			url := EndpointGetProofByHash.Path("http://example.com", th.instance.LogParameters.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("failed creating http request: %v", err)
			}
			q := req.URL.Query()
			q.Add("hash", base64.StdEncoding.EncodeToString(table.breq.Hash))
			q.Add("tree_size", fmt.Sprintf("%d", table.breq.TreeSize))
			req.URL.RawQuery = q.Encode()

			w := httptest.NewRecorder()
			if table.trsp != nil || table.terr != nil {
				th.client.EXPECT().GetInclusionProofByHash(newDeadlineMatcher(), gomock.Any()).Return(table.trsp, table.terr)
			}
			th.getHandler(t, EndpointGetProofByHash).ServeHTTP(w, req)
			if w.Code != table.wantCode {
				t.Errorf("GET(%s)=%d, want http status code %d", url, w.Code, table.wantCode)
			}
			body := w.Body.String()
			if w.Code != http.StatusOK {
				if body != table.wantErrText {
					t.Errorf("GET(%s)=%q, want text %q", url, body, table.wantErrText)
				}
				return
			}

			// status code is http.StatusOK, check response
			var data []byte
			if err := json.Unmarshal([]byte(body), &data); err != nil {
				t.Errorf("failed unmarshaling json: %v, wanted ok", err)
				return
			}
			var item StItem
			if err := item.Unmarshal(data); err != nil {
				t.Errorf("failed unmarshaling StItem: %v, wanted ok", err)
				return
			}
			if item.Format != StFormatInclusionProofV1 {
				t.Errorf("invalid StFormat: got %v, want %v", item.Format, StFormatInclusionProofV1)
			}
			proof := item.InclusionProofV1
			if !bytes.Equal(proof.LogId, th.instance.LogParameters.LogId) {
				t.Errorf("want log id %X, got %X", proof.LogId, th.instance.LogParameters.LogId)
			}
			if proof.TreeSize != uint64(table.breq.TreeSize) {
				t.Errorf("want tree size %d, got %d", table.breq.TreeSize, proof.TreeSize)
			}
			if proof.LeafIndex != 0 {
				t.Errorf("want index %d, got %d", 0, proof.LeafIndex)
			}
			if got, want := len(proof.InclusionPath), len(fixedProof); got != want {
				t.Errorf("want proof length %d, got %d", want, got)
				return
			}
			for i, nh := range proof.InclusionPath {
				if !bytes.Equal(nh.Data, fixedProof[i]) {
					t.Errorf("want proof[%d]=%X, got %X", i, fixedProof[i], nh.Data)
				}
			}
		}()
	}
}

// makeTestLeaf creates add-entry test data
func makeTestLeaf(t *testing.T, name, pemChain, pemKey []byte) ([]byte, []byte) {
	t.Helper()
	key, err := x509util.NewEd25519PrivateKey(pemKey)
	if err != nil {
		t.Fatalf("failed creating ed25519 signing key: %v", err)
	}
	chain, err := x509util.NewCertificateList(pemChain)
	if err != nil {
		t.Fatalf("failed parsing x509 chain: %v", err)
	}
	leaf, err := NewChecksumV1(name, make([]byte, 32)).Marshal()
	if err != nil {
		t.Fatalf("failed creating serialized checksum_v1: %v", err)
	}
	appendix, err := NewAppendix(chain, ed25519.Sign(key, leaf), uint16(tls.Ed25519)).Marshal()
	if err != nil {
		t.Fatalf("failed creating serialized appendix: %v", err)
	}
	return leaf, appendix
}

// makeTestLeafBuffer creates an add-entry data buffer that can be posted.  If
// valid is set to false an invalid signature will be used.
func makeTestLeafBuffer(t *testing.T, name, pemChain, pemKey []byte, valid bool) *bytes.Buffer {
	t.Helper()
	leaf, appendix := makeTestLeaf(t, name, pemChain, pemKey)

	var a Appendix
	if err := a.Unmarshal(appendix); err != nil {
		t.Fatalf("failed unmarshaling Appendix: %v", err)
	}
	chain := make([][]byte, 0, len(a.Chain))
	for _, certificate := range a.Chain {
		chain = append(chain, certificate.Data)
	}
	req := AddEntryRequest{
		Item:            leaf,
		Signature:       a.Signature,
		SignatureScheme: a.SignatureScheme,
		Chain:           chain,
	}
	if !valid {
		req.Signature = []byte{0, 1, 2, 3}
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed marshaling add-entry parameters: %v", err)
	}
	return bytes.NewBuffer(data)
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
