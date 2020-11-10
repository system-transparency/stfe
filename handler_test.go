package stfe

import (
	"crypto"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"crypto/x509"
	"net/http"
	"net/http/httptest"

	"github.com/golang/mock/gomock"
	"github.com/google/certificate-transparency-go/trillian/mockclient"
	"github.com/google/go-cmp/cmp"
	"github.com/google/trillian"
	"github.com/system-transparency/stfe/server/testdata"
	"github.com/system-transparency/stfe/x509util"

	"google.golang.org/protobuf/proto"
)

type testHandler struct {
	mockCtrl *gomock.Controller
	client   *mockclient.MockTrillianLogClient
	instance *Instance
}

func newTestHandler(t *testing.T, signer crypto.Signer) *testHandler {
	anchorList, err := x509util.NewCertificateList(testdata.PemAnchors)
	if err != nil {
		t.Fatalf("failed parsing trust anchors: %v", err)
	}
	ctrl := gomock.NewController(t)
	client := mockclient.NewMockTrillianLogClient(ctrl)
	return &testHandler{
		mockCtrl: ctrl,
		client:   client,
		instance: &Instance{
			Deadline: time.Second * 10, // TODO: fix me?
			Client:   client,
			LogParameters: &LogParameters{
				LogId:      make([]byte, 32),
				TreeId:     0,
				Prefix:     "/test",
				MaxRange:   3,
				MaxChain:   3,
				AnchorPool: x509util.NewCertPool(anchorList),
				AnchorList: anchorList,
				KeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
				Signer:     signer,
				HashType:   crypto.SHA256,
			},
		},
	}
}

func (th *testHandler) getHandlers(t *testing.T) map[string]handler {
	return map[string]handler{
		"get-sth":               handler{instance: th.instance, handler: getSth, endpoint: "get-sth", method: http.MethodGet},
		"get-consistency-proof": handler{instance: th.instance, handler: getConsistencyProof, endpoint: "get-consistency-proof", method: http.MethodGet},
		"get-proof-by-hash":     handler{instance: th.instance, handler: getProofByHash, endpoint: "get-proof-by-hash", method: http.MethodGet},
		"get-anchors":           handler{instance: th.instance, handler: getAnchors, endpoint: "get-anchors", method: http.MethodGet},
		"get-entries":           handler{instance: th.instance, handler: getEntries, endpoint: "get-entries", method: http.MethodGet},
	}
}

func (th *testHandler) getHandler(t *testing.T, endpoint string) handler {
	handler, ok := th.getHandlers(t)[endpoint]
	if !ok {
		t.Fatalf("no such get endpoint: %s", endpoint)
	}
	return handler
}

func (th *testHandler) postHandlers(t *testing.T) map[string]handler {
	return map[string]handler{
		"add-entry": handler{instance: th.instance, handler: addEntry, endpoint: "add-entry", method: http.MethodPost},
	}
}

func (th *testHandler) postHandler(t *testing.T, endpoint string) handler {
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
		t.Run(endpoint, func(t *testing.T) {
			s := httptest.NewServer(handler)
			defer s.Close()

			url := s.URL + strings.Join([]string{th.instance.LogParameters.Prefix, endpoint}, "/")
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
		t.Run(endpoint, func(t *testing.T) {
			s := httptest.NewServer(handler)
			defer s.Close()

			url := s.URL + strings.Join([]string{th.instance.LogParameters.Prefix, endpoint}, "/")
			if rsp, err := http.Get(url); err != nil {
				t.Fatalf("http.Get(%s)=(_,%q), want (_,nil)", url, err)
			} else if rsp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("http.Get(%s)=(%d,nil), want (%d, nil)", url, rsp.StatusCode, http.StatusMethodNotAllowed)
			}
		})
	}
}

func TestGetSth(t *testing.T) {
	for _, table := range []struct {
		description string
		trsp        *trillian.GetLatestSignedLogRootResponse
		terr        error
		wantCode    int
		wantErrText string
	}{
		{
			description: "empty trillian response",
			trsp:        nil,
			terr:        errors.New("back-end failure"),
			wantCode:    http.StatusInternalServerError,
			wantErrText: http.StatusText(http.StatusInternalServerError) + "\n",
		},
	} {
		func() { // run deferred functions at the end of each iteration
			th := newTestHandler(t, nil)
			defer th.mockCtrl.Finish()

			treq := &trillian.GetLatestSignedLogRootRequest{
				LogId: th.instance.LogParameters.TreeId,
			}
			th.client.EXPECT().GetLatestSignedLogRoot(deadlineMatcher{}, compareMatcher{treq}).Return(table.trsp, table.terr)

			url := "http://example.com" + th.instance.LogParameters.Prefix + "/get-sth"
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("failed creating http request: %v", err)
			}

			w := httptest.NewRecorder()
			th.getHandler(t, "get-sth").ServeHTTP(w, req)
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
			// TODO: check that response is in fact valid
		}()
	}
}

type deadlineMatcher struct {
}

func (dm deadlineMatcher) Matches(x interface{}) bool {
	return true // TODO: deadlineMatcher.Matches
}

func (dm deadlineMatcher) String() string {
	return fmt.Sprintf("deadline is: TODO")
}

type compareMatcher struct {
	want interface{}
}

func (cm compareMatcher) Matches(got interface{}) bool {
	return cmp.Equal(got, cm.want, cmp.Comparer(proto.Equal))
}

func (cm compareMatcher) String() string {
	return fmt.Sprintf("equals: TODO")
}
