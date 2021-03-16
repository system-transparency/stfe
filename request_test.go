package stfe

import (
	"bytes"
	//"fmt"
	"reflect"
	"testing"
	//"testing/iotest"

	"net/http"

	"github.com/system-transparency/stfe/testdata"
	"github.com/system-transparency/stfe/types"
)

func TestParseAddEntryV1Request(t *testing.T) {
	lp := newLogParameters(t, nil)
	for _, table := range []struct {
		description string
		breq        *bytes.Buffer
		wantErr     bool
	}{
		{
			description: "invalid: nothing to unpack",
			breq:        bytes.NewBuffer(nil),
			wantErr:     true,
		},
		{
			description: "invalid: not a signed checksum entry",
			breq:        testdata.AddCosignatureBuffer(t, testdata.DefaultSth(t, testdata.Ed25519VkLog), &testdata.Ed25519SkWitness, &testdata.Ed25519VkWitness),
			wantErr:     true,
		},
		{
			description: "invalid: untrusted submitter", // only testdata.Ed25519VkSubmitter is registered by default in newLogParameters()

			breq:    testdata.AddSignedChecksumBuffer(t, testdata.Ed25519SkSubmitter2, testdata.Ed25519VkSubmitter2),
			wantErr: true,
		},
		{
			description: "invalid: signature does not cover message",

			breq:    testdata.AddSignedChecksumBuffer(t, testdata.Ed25519SkSubmitter2, testdata.Ed25519VkSubmitter),
			wantErr: true,
		},
		{
			description: "valid",
			breq:        testdata.AddSignedChecksumBuffer(t, testdata.Ed25519SkSubmitter, testdata.Ed25519VkSubmitter),
		}, // TODO: add test case that disables submitter policy (i.e., unregistered namespaces are accepted)
	} {
		url := EndpointAddEntry.Path("http://example.com", lp.Prefix)
		req, err := http.NewRequest("POST", url, table.breq)
		if err != nil {
			t.Fatalf("failed creating http request: %v", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")

		_, err = lp.parseAddEntryV1Request(req)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got errror %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
	}
}

func TestParseAddCosignatureV1Request(t *testing.T) {
	lp := newLogParameters(t, nil)
	for _, table := range []struct {
		description string
		breq        *bytes.Buffer
		wantErr     bool
	}{
		{
			description: "invalid: nothing to unpack",
			breq:        bytes.NewBuffer(nil),
			wantErr:     true,
		},
		{
			description: "invalid: not a cosigned sth",
			breq:        testdata.AddSignedChecksumBuffer(t, testdata.Ed25519SkSubmitter, testdata.Ed25519VkSubmitter),
			wantErr:     true,
		},
		{
			description: "invalid: no cosignature",
			breq:        testdata.AddCosignatureBuffer(t, testdata.DefaultSth(t, testdata.Ed25519VkLog), &testdata.Ed25519SkWitness, nil),
			wantErr:     true,
		},
		{
			description: "invalid: untrusted witness", // only testdata.Ed25519VkWitness is registered by default in newLogParameters()
			breq:        testdata.AddCosignatureBuffer(t, testdata.DefaultSth(t, testdata.Ed25519VkLog), &testdata.Ed25519SkWitness2, &testdata.Ed25519VkWitness2),
			wantErr:     true,
		},
		{
			description: "invalid: signature does not cover message",
			breq:        testdata.AddCosignatureBuffer(t, testdata.DefaultSth(t, testdata.Ed25519VkLog), &testdata.Ed25519SkWitness2, &testdata.Ed25519VkWitness),
			wantErr:     true,
		},
		{
			description: "valid",
			breq:        testdata.AddCosignatureBuffer(t, testdata.DefaultSth(t, testdata.Ed25519VkLog), &testdata.Ed25519SkWitness, &testdata.Ed25519VkWitness),
		}, // TODO: add test case that disables witness policy (i.e., unregistered namespaces are accepted)
	} {
		url := EndpointAddCosignature.Path("http://example.com", lp.Prefix)
		req, err := http.NewRequest("POST", url, table.breq)
		if err != nil {
			t.Fatalf("failed creating http request: %v", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")

		_, err = lp.parseAddCosignatureV1Request(req)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got errror %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
	}
}

func TestNewGetConsistencyProofRequest(t *testing.T) {
	lp := newLogParameters(t, nil)
	for _, table := range []struct {
		description string
		req         *types.GetConsistencyProofV1
		wantErr     bool
	}{
		{
			description: "invalid: nothing to unpack",
			req:         nil,
			wantErr:     true,
		},
		{
			description: "invalid: first must be larger than zero",
			req:         &types.GetConsistencyProofV1{First: 0, Second: 0},
			wantErr:     true,
		},
		{
			description: "invalid: second must be larger than first",
			req:         &types.GetConsistencyProofV1{First: 2, Second: 1},
			wantErr:     true,
		},
		{
			description: "valid",
			req:         &types.GetConsistencyProofV1{First: 1, Second: 2},
		},
	} {
		var buf *bytes.Buffer
		if table.req == nil {
			buf = bytes.NewBuffer(nil)
		} else {
			buf = bytes.NewBuffer(marshal(t, *table.req))
		}

		url := EndpointGetConsistencyProof.Path("http://example.com", lp.Prefix)
		req, err := http.NewRequest("POST", url, buf)
		if err != nil {
			t.Fatalf("failed creating http request: %v", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")

		_, err = lp.parseGetConsistencyProofV1Request(req)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got errror %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
	}
}

func TestNewGetProofByHashRequest(t *testing.T) {
	lp := newLogParameters(t, nil)
	for _, table := range []struct {
		description string
		req         *types.GetProofByHashV1
		wantErr     bool
	}{
		{
			description: "invalid: nothing to unpack",
			req:         nil,
			wantErr:     true,
		},
		{
			description: "invalid: no entry in an empty tree",
			req:         &types.GetProofByHashV1{TreeSize: 0, Hash: testdata.LeafHash},
			wantErr:     true,
		},
		{
			description: "valid",
			req:         &types.GetProofByHashV1{TreeSize: 1, Hash: testdata.LeafHash},
		},
	} {
		var buf *bytes.Buffer
		if table.req == nil {
			buf = bytes.NewBuffer(nil)
		} else {
			buf = bytes.NewBuffer(marshal(t, *table.req))
		}

		url := EndpointGetProofByHash.Path("http://example.com", lp.Prefix)
		req, err := http.NewRequest("POST", url, buf)
		if err != nil {
			t.Fatalf("failed creating http request: %v", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")

		_, err = lp.parseGetProofByHashV1Request(req)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got errror %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
	}
}

func TestParseGetEntriesV1Request(t *testing.T) {
	lp := newLogParameters(t, nil)
	for _, table := range []struct {
		description string
		req         *types.GetEntriesV1
		wantErr     bool
		wantReq     *types.GetEntriesV1
	}{
		{
			description: "invalid: nothing to unpack",
			req:         nil,
			wantErr:     true,
		},
		{
			description: "invalid: start must be larger than end",
			req:         &types.GetEntriesV1{Start: 1, End: 0},
			wantErr:     true,
		},
		{
			description: "valid: want truncated range",
			req:         &types.GetEntriesV1{Start: 0, End: uint64(testdata.MaxRange)},
			wantReq:     &types.GetEntriesV1{Start: 0, End: uint64(testdata.MaxRange) - 1},
		},
		{
			description: "valid",
			req:         &types.GetEntriesV1{Start: 0, End: 0},
			wantReq:     &types.GetEntriesV1{Start: 0, End: 0},
		},
	} {
		var buf *bytes.Buffer
		if table.req == nil {
			buf = bytes.NewBuffer(nil)
		} else {
			buf = bytes.NewBuffer(marshal(t, *table.req))
		}

		url := EndpointGetEntries.Path("http://example.com", lp.Prefix)
		req, err := http.NewRequest("POST", url, buf)
		if err != nil {
			t.Fatalf("failed creating http request: %v", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")

		output, err := lp.parseGetEntriesV1Request(req)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got errror %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := output, table.wantReq; !reflect.DeepEqual(got, want) {
			t.Errorf("got request\n%v\n\tbut wanted\n%v\n\t in test %q", got, want, table.description)
		}
	}
}

func TestUnpackOctetPost(t *testing.T) {
	for _, table := range []struct {
		description string
		req         *http.Request
		out         interface{}
		wantErr     bool
	}{
		//{
		//	description: "invalid: cannot read request body",
		//	req: func() *http.Request {
		//		req, err := http.NewRequest(http.MethodPost, "", iotest.ErrReader(fmt.Errorf("bad reader")))
		//		if err != nil {
		//			t.Fatalf("must make new http request: %v", err)
		//		}
		//		return req
		//	}(),
		//	out:     &types.StItem{},
		//	wantErr: true,
		//}, // testcase requires Go 1.16
		{
			description: "invalid: cannot unmarshal",
			req: func() *http.Request {
				req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer(nil))
				if err != nil {
					t.Fatalf("must make new http request: %v", err)
				}
				return req
			}(),
			out:     &types.StItem{},
			wantErr: true,
		},
		{
			description: "valid",
			req: func() *http.Request {
				req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte{0}))
				if err != nil {
					t.Fatalf("must make new http request: %v", err)
				}
				return req
			}(),
			out: &struct{ SomeUint8 uint8 }{},
		},
	} {
		err := unpackOctetPost(table.req, table.out)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q", got, want, table.description)
		}
	}
}

func marshal(t *testing.T, out interface{}) []byte {
	b, err := types.Marshal(out)
	if err != nil {
		t.Fatalf("must marshal: %v", err)
	}
	return b
}
