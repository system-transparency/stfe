package stfe

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/system-transparency/stfe/pkg/mocks"
	"github.com/system-transparency/stfe/pkg/types"
)

var (
	testWitVK  = [types.VerificationKeySize]byte{}
	testConfig = Config{
		LogID:    hex.EncodeToString(types.Hash([]byte("logid"))[:]),
		TreeID:   0,
		Prefix:   "testonly",
		MaxRange: 3,
		Deadline: 10,
		Interval: 10,
		Witnesses: map[[types.HashSize]byte][types.VerificationKeySize]byte{
			*types.Hash(testWitVK[:]): testWitVK,
		},
	}
	testSTH = &types.SignedTreeHead{
		TreeHead: types.TreeHead{
			Timestamp: 0,
			TreeSize:  0,
			RootHash:  types.Hash(nil),
		},
		SigIdent: []*types.SigIdent{
			&types.SigIdent{
				Signature: &[types.SignatureSize]byte{},
				KeyHash:   &[types.HashSize]byte{},
			},
		},
	}
)

func mustHandle(t *testing.T, i Instance, e types.Endpoint) Handler {
	for _, handler := range i.Handlers() {
		if handler.Endpoint == e {
			return handler
		}
	}
	t.Fatalf("must handle endpoint: %v", e)
	return Handler{}
}

func TestAddLeaf(t *testing.T) {
	buf := func() io.Reader {
		// A valid leaf request that was created manually
		return bytes.NewBufferString(fmt.Sprintf(
			"%s%s%s%s"+"%s%s%s%s"+"%s%s%s%s"+"%s%s%s%s"+"%s%s%s%s",
			types.ShardHint, types.Delim, "0", types.EOL,
			types.Checksum, types.Delim, "0000000000000000000000000000000000000000000000000000000000000000", types.EOL,
			types.SignatureOverMessage, types.Delim, "4cb410a4d48f52f761a7c01abcc28fd71811b84ded5403caed5e21b374f6aac9637cecd36828f17529fd503413d30ab66d7bb37a31dbf09a90d23b9241c45009", types.EOL,
			types.VerificationKey, types.Delim, "f2b7a00b625469d32502e06e8b7fad1ef258d4ad0c6cd87b846142ab681957d5", types.EOL,
			types.DomainHint, types.Delim, "example.com", types.EOL,
		))
	}
	for _, table := range []struct {
		description string
		ascii       io.Reader // buffer used to populate HTTP request
		expect      bool      // set if a mock answer is expected
		err         error     // error from Trillian client
		wantCode    int       // HTTP status ok
	}{
		{
			description: "invalid: bad request (parser error)",
			ascii:       bytes.NewBufferString("key=value\n"),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (signature error)",
			ascii: bytes.NewBufferString(fmt.Sprintf(
				"%s%s%s%s"+"%s%s%s%s"+"%s%s%s%s"+"%s%s%s%s"+"%s%s%s%s",
				types.ShardHint, types.Delim, "1", types.EOL,
				types.Checksum, types.Delim, "1111111111111111111111111111111111111111111111111111111111111111", types.EOL,
				types.SignatureOverMessage, types.Delim, "4cb410a4d48f52f761a7c01abcc28fd71811b84ded5403caed5e21b374f6aac9637cecd36828f17529fd503413d30ab66d7bb37a31dbf09a90d23b9241c45009", types.EOL,
				types.VerificationKey, types.Delim, "f2b7a00b625469d32502e06e8b7fad1ef258d4ad0c6cd87b846142ab681957d5", types.EOL,
				types.DomainHint, types.Delim, "example.com", types.EOL,
			)),
			wantCode: http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			ascii:       buf(),
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			ascii:       buf(),
			expect:      true,
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocks.NewMockClient(ctrl)
			if table.expect {
				client.EXPECT().AddLeaf(gomock.Any(), gomock.Any()).Return(table.err)
			}
			i := Instance{
				Config: testConfig,
				Client: client,
			}

			// Create HTTP request
			url := types.EndpointAddLeaf.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("POST", url, table.ascii)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointAddLeaf).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestAddCosignature(t *testing.T) {
	buf := func() io.Reader {
		return bytes.NewBufferString(fmt.Sprintf(
			"%s%s%x%s"+"%s%s%x%s",
			types.Signature, types.Delim, make([]byte, types.SignatureSize), types.EOL,
			types.KeyHash, types.Delim, *types.Hash(testWitVK[:]), types.EOL,
		))
	}
	for _, table := range []struct {
		description string
		ascii       io.Reader // buffer used to populate HTTP request
		expect      bool      // set if a mock answer is expected
		err         error     // error from Trillian client
		wantCode    int       // HTTP status ok
	}{
		{
			description: "invalid: bad request (parser error)",
			ascii:       bytes.NewBufferString("key=value\n"),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (unknown witness)",
			ascii: bytes.NewBufferString(fmt.Sprintf(
				"%s%s%x%s"+"%s%s%x%s",
				types.Signature, types.Delim, make([]byte, types.SignatureSize), types.EOL,
				types.KeyHash, types.Delim, *types.Hash(testWitVK[1:]), types.EOL,
			)),
			wantCode: http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			ascii:       buf(),
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "valid",
			ascii:       buf(),
			expect:      true,
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			stateman := mocks.NewMockStateManager(ctrl)
			if table.expect {
				stateman.EXPECT().AddCosignature(gomock.Any(), gomock.Any(), gomock.Any()).Return(table.err)
			}
			i := Instance{
				Config:   testConfig,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointAddCosignature.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("POST", url, table.ascii)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointAddCosignature).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetTreeHeadLatest(t *testing.T) {
	for _, table := range []struct {
		description string
		expect      bool                  // set if a mock answer is expected
		rsp         *types.SignedTreeHead // signed tree head from Trillian client
		err         error                 // error from Trillian client
		wantCode    int                   // HTTP status ok
	}{
		{
			description: "invalid: backend failure",
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			expect:      true,
			rsp:         testSTH,
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			stateman := mocks.NewMockStateManager(ctrl)
			if table.expect {
				stateman.EXPECT().Latest(gomock.Any()).Return(table.rsp, table.err)
			}
			i := Instance{
				Config:   testConfig,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointGetTreeHeadLatest.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointGetTreeHeadLatest).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetTreeToSign(t *testing.T) {
	for _, table := range []struct {
		description string
		expect      bool                  // set if a mock answer is expected
		rsp         *types.SignedTreeHead // signed tree head from Trillian client
		err         error                 // error from Trillian client
		wantCode    int                   // HTTP status ok
	}{
		{
			description: "invalid: backend failure",
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			expect:      true,
			rsp:         testSTH,
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			stateman := mocks.NewMockStateManager(ctrl)
			if table.expect {
				stateman.EXPECT().ToSign(gomock.Any()).Return(table.rsp, table.err)
			}
			i := Instance{
				Config:   testConfig,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointGetTreeHeadToSign.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointGetTreeHeadToSign).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetTreeCosigned(t *testing.T) {
	for _, table := range []struct {
		description string
		expect      bool                  // set if a mock answer is expected
		rsp         *types.SignedTreeHead // signed tree head from Trillian client
		err         error                 // error from Trillian client
		wantCode    int                   // HTTP status ok
	}{
		{
			description: "invalid: backend failure",
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			expect:      true,
			rsp:         testSTH,
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			stateman := mocks.NewMockStateManager(ctrl)
			if table.expect {
				stateman.EXPECT().Cosigned(gomock.Any()).Return(table.rsp, table.err)
			}
			i := Instance{
				Config:   testConfig,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointGetTreeHeadCosigned.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointGetTreeHeadCosigned).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetConsistencyProof(t *testing.T) {
	buf := func(oldSize, newSize int) io.Reader {
		return bytes.NewBufferString(fmt.Sprintf(
			"%s%s%d%s"+"%s%s%d%s",
			types.OldSize, types.Delim, oldSize, types.EOL,
			types.NewSize, types.Delim, newSize, types.EOL,
		))
	}
	// values in testProof are not relevant for the test, just need a path
	testProof := &types.ConsistencyProof{
		OldSize: 1,
		NewSize: 2,
		Path: []*[types.HashSize]byte{
			types.Hash(nil),
		},
	}
	for _, table := range []struct {
		description string
		ascii       io.Reader               // buffer used to populate HTTP request
		expect      bool                    // set if a mock answer is expected
		rsp         *types.ConsistencyProof // consistency proof from Trillian client
		err         error                   // error from Trillian client
		wantCode    int                     // HTTP status ok
	}{
		{
			description: "invalid: bad request (parser error)",
			ascii:       bytes.NewBufferString("key=value\n"),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "valid",
			ascii:       buf(1, 2),
			expect:      true,
			rsp:         testProof,
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocks.NewMockClient(ctrl)
			if table.expect {
				client.EXPECT().GetConsistencyProof(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			}
			i := Instance{
				Config: testConfig,
				Client: client,
			}

			// Create HTTP request
			url := types.EndpointGetConsistencyProof.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("POST", url, table.ascii)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointGetConsistencyProof).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetInclusionProof(t *testing.T) {
}

func TestGetLeaves(t *testing.T) {
}
