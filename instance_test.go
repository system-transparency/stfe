package stfe

import (
	"bytes"
	"testing"
	"time"

	"crypto"
	"crypto/ed25519"

	"github.com/system-transparency/stfe/namespace"
	"github.com/system-transparency/stfe/namespace/testdata"
)

var (
	testLogId          = append([]byte{0x00, 0x01, 0x20}, testdata.Ed25519Vk3...)
	testTreeId         = int64(0)
	testMaxRange       = int64(3)
	testPrefix         = "test"
	testHashType       = crypto.SHA256
	testSignature      = make([]byte, 32)
	testNodeHash       = make([]byte, 32)
	testMessage        = []byte("test message")
	testPackage        = []byte("foobar")
	testChecksum       = make([]byte, 32)
	testTreeSize       = uint64(128)
	testTreeSizeLarger = uint64(256)
	testTimestamp      = uint64(0)
	testProof          = [][]byte{
		testNodeHash,
		testNodeHash,
	}
	testIndex    = uint64(0)
	testHashLen  = 31
	testDeadline = time.Second * 5
	testInterval = time.Second * 10
)

// TestNewLogParamters checks that invalid ones are rejected and that a valid
// set of parameters are accepted.
func TestNewLogParameters(t *testing.T) {
	testLogId := mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk3)
	namespaces := mustNewNamespacePool(t, []*namespace.Namespace{
		mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk),
	})
	witnesses := mustNewNamespacePool(t, []*namespace.Namespace{})
	signer := ed25519.PrivateKey(testdata.Ed25519Sk)
	for _, table := range []struct {
		description string
		logId       *namespace.Namespace
		maxRange    int64
		signer      crypto.Signer
		wantErr     bool
	}{
		{
			description: "invalid signer: nil",
			logId:       testLogId,
			maxRange:    testMaxRange,
			signer:      nil,
			wantErr:     true,
		},
		{
			description: "invalid max range",
			logId:       testLogId,
			maxRange:    0,
			signer:      signer,
			wantErr:     true,
		},
		{
			description: "invalid log identifier",
			logId: &namespace.Namespace{
				Format: namespace.NamespaceFormatEd25519V1,
				NamespaceEd25519V1: &namespace.NamespaceEd25519V1{
					Namespace: make([]byte, 31), // too short
				},
			},
			maxRange: testMaxRange,
			signer:   signer,
			wantErr:  true,
		},
		{
			description: "valid log parameters",
			logId:       testLogId,
			maxRange:    testMaxRange,
			signer:      signer,
		},
	} {
		lp, err := NewLogParameters(table.signer, table.logId, testTreeId, testPrefix, namespaces, witnesses, table.maxRange, testInterval, testDeadline)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error=%v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		lid, err := table.logId.Marshal()
		if err != nil {
			t.Fatalf("must marshal log id: %v", err)
		}

		if got, want := lp.LogId, lid; !bytes.Equal(got, want) {
			t.Errorf("got log id %X but wanted %X in test %q", got, want, table.description)
		}
		if got, want := lp.TreeId, testTreeId; got != want {
			t.Errorf("got tree id %d but wanted %d in test %q", got, want, table.description)
		}
		if got, want := lp.Prefix, testPrefix; got != want {
			t.Errorf("got prefix %s but wanted %s in test %q", got, want, table.description)
		}
		if got, want := lp.MaxRange, testMaxRange; got != want {
			t.Errorf("got max range %d but wanted %d in test %q", got, want, table.description)
		}
		if got, want := len(lp.Submitters.List()), len(namespaces.List()); got != want {
			t.Errorf("got %d anchors but wanted %d in test %q", got, want, table.description)
		}
		if got, want := len(lp.Witnesses.List()), len(witnesses.List()); got != want {
			t.Errorf("got %d anchors but wanted %d in test %q", got, want, table.description)
		}
	}
}

// TestHandlers checks that we configured all endpoints and that there are no
// unexpected ones.
func TestHandlers(t *testing.T) {
	endpoints := map[Endpoint]bool{
		EndpointAddEntry:            false,
		EndpointGetEntries:          false,
		EndpointGetLatestSth:        false,
		EndpointGetProofByHash:      false,
		EndpointGetConsistencyProof: false,
		EndpointGetAnchors:          false,
		EndpointGetStableSth:        false,
		EndpointGetCosignedSth:      false,
		EndpointAddCosignature:      false,
	}
	i := NewInstance(makeTestLogParameters(t, nil), nil, nil)
	for _, handler := range i.Handlers() {
		if _, ok := endpoints[handler.endpoint]; !ok {
			t.Errorf("got unexpected endpoint: %s", handler.endpoint)
		}
		endpoints[handler.endpoint] = true
	}
	for endpoint, ok := range endpoints {
		if !ok {
			t.Errorf("endpoint %s is not configured", endpoint)
		}
	}
}

// TestEndpointPath checks that the endpoint path builder works as expected
func TestEndpointPath(t *testing.T) {
	base, prefix := "http://example.com", "test"
	for _, table := range []struct {
		endpoint Endpoint
		want     string
	}{
		{
			endpoint: EndpointAddEntry,
			want:     "http://example.com/test/add-entry",
		},
		{
			endpoint: EndpointGetEntries,
			want:     "http://example.com/test/get-entries",
		},
		{
			endpoint: EndpointGetProofByHash,
			want:     "http://example.com/test/get-proof-by-hash",
		},
		{
			endpoint: EndpointGetConsistencyProof,
			want:     "http://example.com/test/get-consistency-proof",
		},
		{
			endpoint: EndpointGetLatestSth,
			want:     "http://example.com/test/get-latest-sth",
		},
		{
			endpoint: EndpointGetAnchors,
			want:     "http://example.com/test/get-anchors",
		},
		{
			endpoint: EndpointGetStableSth,
			want:     "http://example.com/test/get-stable-sth",
		},
		{
			endpoint: EndpointGetCosignedSth,
			want:     "http://example.com/test/get-cosigned-sth",
		},
		{
			endpoint: EndpointAddCosignature,
			want:     "http://example.com/test/add-cosignature",
		},
	} {
		if got, want := table.endpoint.Path(base, prefix), table.want; got != want {
			t.Errorf("got %s but wanted %s with multiple components", got, want)
		}
		if got, want := table.endpoint.Path(base+"/"+prefix), table.want; got != want {
			t.Errorf("got %s but wanted %s with one component", got, want)
		}
	}
}

func mustNewLogId(t *testing.T, namespace *namespace.Namespace) []byte {
	b, err := namespace.Marshal()
	if err != nil {
		t.Fatalf("must marshal log id: %v", err)
	}
	return b
}

func mustNewNamespaceEd25519V1(t *testing.T, vk []byte) *namespace.Namespace {
	namespace, err := namespace.NewNamespaceEd25519V1(vk)
	if err != nil {
		t.Fatalf("must make ed25519 namespace: %v", err)
	}
	return namespace
}

func mustNewNamespacePool(t *testing.T, anchors []*namespace.Namespace) *namespace.NamespacePool {
	namespaces, err := namespace.NewNamespacePool(anchors)
	if err != nil {
		t.Fatalf("must make namespaces: %v", err)
	}
	return namespaces
}

// makeTestLogParameters makes a collection of test log parameters.
//
// The log's identity is based on testdata.Ed25519{Vk3,Sk3}.  The log's accepted
// submitters are based on testdata.Ed25519Vk.  The log's accepted witnesses are
// based on testdata.Ed25519Vk.  The remaining log parameters are based on the
// global test* variables in this file.
//
// For convenience the passed signer is optional (i.e., it may be nil).
func makeTestLogParameters(t *testing.T, signer crypto.Signer) *LogParameters {
	return &LogParameters{
		LogId:    mustNewLogId(t, mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk3)),
		TreeId:   testTreeId,
		Prefix:   testPrefix,
		MaxRange: testMaxRange,
		Submitters: mustNewNamespacePool(t, []*namespace.Namespace{
			mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk),
		}),
		Witnesses: mustNewNamespacePool(t, []*namespace.Namespace{
			mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk),
		}),
		Signer:   signer,
		HashType: testHashType,
	}
}
