package stfe

import (
	"fmt"
	"testing"

	"net/http"
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
			end:         fmt.Sprintf("%d", testMaxRange-1),
		},
	} {
		req, err := http.NewRequest("GET", "http://example.com/"+lp.Prefix+"/get-entries", nil)
		q := req.URL.Query()
		q.Add("start", table.start)
		q.Add("end", table.end)
		req.URL.RawQuery = q.Encode()

		rsp, err := lp.newGetEntriesRequest(req)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error is %v but wanted %v in test %q: %v", got, want, table.description, err)
		}

		if n := rsp.End - rsp.Start + 1; n > int64(testMaxRange) {
			t.Errorf("get-entries range is too large in test %q: %d > %d", table.description, n, testMaxRange)
		}
	}
}

// TODO: TestNewGetProofByHashRequest
func TestNewGetProofByHashRequest(t *testing.T) {
}

// TODO: TestNewGetConsistencyProofRequest
func TestNewGetConsistencyProofRequest(t *testing.T) {
}

// TODO: TestNewGetEntryResponse
func TestNewGetEntriesResponse(t *testing.T) {
}

// TODO: TestNewGetAnchorsResponse
func TestNewGetAnchorsResponse(t *testing.T) {
}
