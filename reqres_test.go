package stfe

import (
	"bytes"
	"fmt"
	"strconv"
	"testing"

	"crypto/x509"
	"net/http"

	"github.com/google/trillian"
	"github.com/system-transparency/stfe/testdata"
)

// TODO: TestNewAddEntryRequest
func TestNewAddEntryRequest(t *testing.T) {
}

func TestNewGetEntriesRequest(t *testing.T) {
	lp := makeTestLogParameters(t, nil)
	for _, table := range []struct {
		description string
		start       string
		end         string
		wantErr     bool
	}{
		{
			description: "bad request: start must be an integer",
			start:       "start",
			end:         "10",
			wantErr:     true,
		},
		{
			description: "bad request: end must be an integer",
			start:       "10",
			end:         "end",
			wantErr:     true,
		},
		{
			description: "bad request: start must not be negative",
			start:       "-1",
			end:         "10",
			wantErr:     true,
		},
		{
			description: "bad request: start must be larger than end",
			start:       "1",
			end:         "0",
			wantErr:     true,
		},
		{
			description: "ok request but bad response: expected truncated",
			start:       "0",
			end:         fmt.Sprintf("%d", testMaxRange),
		},
		{
			description: "ok request and response",
			start:       "0",
			end:         "0",
		},
		{
			description: "ok request and response",
			start:       "0",
			end:         fmt.Sprintf("%d", testMaxRange-1),
		},
	} {
		r, err := http.NewRequest("GET", "http://example.com/"+lp.Prefix+"/get-entries", nil)
		if err != nil {
			t.Fatalf("must make http request in test %q: %v", table.description, err)
		}
		q := r.URL.Query()
		q.Add("start", table.start)
		q.Add("end", table.end)
		r.URL.RawQuery = q.Encode()

		req, err := lp.newGetEntriesRequest(r)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error is %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}

		if got, want := req.Start, mustParseInt64(t, table.start); got != want {
			t.Errorf("got start %d but wanted %d in test %q", got, want, table.description)
		}
		if got, want := req.End, min(mustParseInt64(t, table.end), req.Start+testMaxRange-1); got != want {
			t.Errorf("got end %d but wanted %d in test %q", got, want, table.description)
		}
	}
}

func TestNewGetProofByHashRequest(t *testing.T) {
	lp := makeTestLogParameters(t, nil)
	for _, table := range []struct {
		description string
		treeSize    string
		hash        string
		wantErr     bool
	}{
		{
			description: "bad request: tree size must be an integer",
			treeSize:    "treeSize",
			hash:        b64(testNodeHash),
			wantErr:     true,
		},
		{
			description: "bad request: tree size must be larger than zero",
			treeSize:    "0",
			hash:        b64(testNodeHash),
			wantErr:     true,
		},
		{
			description: "bad request: hash is not base64",
			treeSize:    "1",
			hash:        "<(^_^)>",
			wantErr:     true,
		},
		{
			description: "bad request: invalid node hash (too small)",
			treeSize:    "1",
			hash:        b64(testNodeHash[1:]),
			wantErr:     true,
		},
		{
			description: "bad request: invalid node hash (too large)",
			treeSize:    "1",
			hash:        b64(append(testNodeHash, byte(0))),
			wantErr:     true,
		},
		{
			description: "ok request",
			treeSize:    "1",
			hash:        b64(testNodeHash),
		},
	} {
		r, err := http.NewRequest("GET", "http://example.com/"+lp.Prefix+"/get-proof-by-hash", nil)
		if err != nil {
			t.Fatalf("must make http request in test %q: %v", table.description, err)
		}
		q := r.URL.Query()
		q.Add("tree_size", table.treeSize)
		q.Add("hash", table.hash)
		r.URL.RawQuery = q.Encode()

		req, err := lp.newGetProofByHashRequest(r)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error is %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}

		if got, want := req.TreeSize, mustParseInt64(t, table.treeSize); got != want {
			t.Errorf("got treeSize %d but wanted %d in test %q", got, want, table.description)
		}
		if got, want := req.Hash, mustDeb64(t, table.hash); !bytes.Equal(got, want) {
			t.Errorf("got hash %X but wanted %X in test %q", got, want, table.description)
		}
	}
}

func TestNewGetConsistencyProofRequest(t *testing.T) {
	lp := makeTestLogParameters(t, nil)
	for _, table := range []struct {
		description string
		first       string
		second      string
		wantErr     bool
	}{
		{
			description: "bad reuqest: first must be an integer",
			first:       "first",
			second:      "1",
			wantErr:     true,
		},
		{
			description: "bad request: second must be an integer",
			first:       "1",
			second:      "second",
			wantErr:     true,
		},
		{
			description: "bad request: first must be larger than zero",
			first:       "0",
			second:      "2",
			wantErr:     true,
		},
		{
			description: "bad request: second must be larger than firsst",
			first:       "2",
			second:      "1",
			wantErr:     true,
		},
		{
			description: "ok request",
			first:       "1",
			second:      "2",
		},
	} {
		r, err := http.NewRequest("GET", "http://example.com/"+lp.Prefix+"/get-consistency-proof", nil)
		if err != nil {
			t.Fatalf("must make http request in test %q: %v", table.description, err)
		}
		q := r.URL.Query()
		q.Add("first", table.first)
		q.Add("second", table.second)
		r.URL.RawQuery = q.Encode()

		req, err := lp.newGetConsistencyProofRequest(r)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error is %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}

		if got, want := req.First, mustParseInt64(t, table.first); got != want {
			t.Errorf("got first %d but wanted %d in test %q", got, want, table.description)
		}
		if got, want := req.Second, mustParseInt64(t, table.second); got != want {
			t.Errorf("got second %d but wanted %d in test %q", got, want, table.description)
		}
	}
}

func TestNewGetEntryResponse(t *testing.T) {
	lp := makeTestLogParameters(t, nil)

	var appendix Appendix
	leaf, app := makeTestLeaf(t, testPackage, testdata.FirstPemChain, testdata.FirstPemChainKey)
	if err := appendix.Unmarshal(app); err != nil {
		t.Fatalf("must unmarshal appendix: %v", err)
	}
	if _, err := lp.newGetEntryResponse(leaf, app[1:]); err == nil {
		t.Errorf("got no error invalid appendix")
	}

	// Valid response
	rsp, err := lp.newGetEntryResponse(leaf, app)
	if err != nil {
		t.Errorf("got error %v but wanted none", err)
		return
	}
	if got, want := rsp.Item, leaf; !bytes.Equal(got, want) {
		t.Errorf("got leaf %X but wanted %X", got, want)
	}
	if got, want := rsp.Signature, appendix.Signature; !bytes.Equal(got, want) {
		t.Errorf("got signature %X but wanted %X", got, want)
	}
	if got, want := rsp.SignatureScheme, appendix.SignatureScheme; got != want {
		t.Errorf("got signature scheme %d but wanted %d", got, want)
	}
	if got, want := len(rsp.Chain), len(appendix.Chain); got != want {
		t.Errorf("got chain length %d but wanted %d", got, want)
	}
	for i, n := 0, len(rsp.Chain); i < n; i++ {
		if got, want := rsp.Chain[i], appendix.Chain[i].Data; !bytes.Equal(got, want) {
			t.Errorf("got chain[%d]=%X but wanted %X", i, got, want)
		}
	}
}

func TestNewGetEntriesResponse(t *testing.T) {
	lp := makeTestLogParameters(t, nil)

	// Invalid
	leaf := makeTrillianQueueLeafResponse(t, testPackage, testdata.FirstPemChain, testdata.FirstPemChainKey, false).QueuedLeaf.Leaf
	leaf.ExtraData = leaf.ExtraData[1:]
	if _, err := lp.newGetEntriesResponse([]*trillian.LogLeaf{leaf}); err == nil {
		t.Errorf("got no error for invalid appendix")
	}

	// Valid, including empty
	for n, numEntries := 0, 5; n < numEntries; n++ {
		leaves := make([]*trillian.LogLeaf, 0, n)
		for i := 0; i < n; i++ {
			leaves = append(leaves, makeTrillianQueueLeafResponse(t, []byte(fmt.Sprintf("%s-%d", testPackage, i)), testdata.FirstPemChain, testdata.FirstPemChainKey, false).QueuedLeaf.Leaf)
		}
		if rsp, err := lp.newGetEntriesResponse(leaves); err != nil {
			t.Errorf("got error for %d valid leaves: %v", n, err)
		} else if got, want := len(rsp), n; got != want {
			t.Errorf("got %d leaves but wanted %d", got, want)
		}
		// note that we tested actual leaf contents in TestNewGetEntryResponse
	}
}

func TestNewGetAnchorsResponse(t *testing.T) {
	rawAnchors := makeTestLogParameters(t, nil).newGetAnchorsResponse()
	if got, want := len(rawAnchors), testdata.NumPemAnchors; got != want {
		t.Errorf("got %d anchors but wanted %d", got, want)
	}
	for _, rawAnchor := range rawAnchors {
		if _, err := x509.ParseCertificate(rawAnchor); err != nil {
			t.Errorf("invalid trust anchor %X: %v", rawAnchor, err)
		}
	}
}

func mustParseInt64(t *testing.T, num string) int64 {
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil {
		t.Fatalf("must parse int: %v", err)
	}
	return n
}

func mustDeb64(t *testing.T, str string) []byte {
	b, err := deb64(str)
	if err != nil {
		t.Fatalf("must base64 decode: %v", err)
	}
	return b
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
