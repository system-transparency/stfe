package stfe

import (
	"bytes"
	"testing"

	"crypto"
	"crypto/sha256"
	"crypto/x509"

	cttestdata "github.com/google/certificate-transparency-go/trillian/testdata"
	"github.com/system-transparency/stfe/x509util"
	"github.com/system-transparency/stfe/x509util/testdata"
)

var (
	testHashLen     = 31
	testMaxRange    = int64(3)
	testMaxChain    = int64(3)
	testTreeId      = int64(0)
	testPrefix      = "test"
	testHashType    = crypto.SHA256
	testExtKeyUsage = []x509.ExtKeyUsage{}
)

func TestNewLogParameters(t *testing.T) {
	anchors, err := x509util.NewCertificateList(testdata.TrustAnchors)
	if err != nil {
		t.Fatalf("must decode trust anchors: %v", err)
	}
	signer, err := x509util.NewEd25519PrivateKey(testdata.LogPrivateKey)
	if err != nil {
		t.Fatalf("must decode private key: %v", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("must encode public key: %v", err)
	}
	hasher := sha256.New()
	hasher.Write(pub)
	logId := hasher.Sum(nil)
	for _, table := range []struct {
		description string
		treeId      int64
		prefix      string
		maxRange    int64
		maxChain    int64
		anchors     []*x509.Certificate
		signer      crypto.Signer
		wantErr     bool
	}{
		{
			description: "invalid signer: nil",
			treeId:      testTreeId,
			prefix:      testPrefix,
			maxRange:    0,
			maxChain:    testMaxChain,
			anchors:     anchors,
			signer:      nil,
			wantErr:     true,
		},
		{
			description: "no trust anchors",
			treeId:      testTreeId,
			prefix:      testPrefix,
			maxRange:    testMaxRange,
			maxChain:    testMaxChain,
			anchors:     []*x509.Certificate{},
			signer:      signer,
			wantErr:     true,
		},
		{
			description: "invalid max range",
			treeId:      testTreeId,
			prefix:      testPrefix,
			maxRange:    0,
			maxChain:    testMaxChain,
			anchors:     anchors,
			signer:      signer,
			wantErr:     true,
		},
		{
			description: "invalid max chain",
			treeId:      testTreeId,
			prefix:      testPrefix,
			maxRange:    testMaxRange,
			maxChain:    0,
			anchors:     anchors,
			signer:      signer,
			wantErr:     true,
		},
		{
			description: "public key marshal failure",
			treeId:      testTreeId,
			prefix:      testPrefix,
			maxRange:    testMaxRange,
			maxChain:    testMaxChain,
			anchors:     anchors,
			signer:      cttestdata.NewSignerWithFixedSig("no pub", testSignature),
			wantErr:     true,
		},
		{
			description: "valid log parameters",
			treeId:      testTreeId,
			prefix:      testPrefix,
			maxRange:    testMaxRange,
			maxChain:    testMaxChain,
			anchors:     anchors,
			signer:      signer,
		},
	} {
		lp, err := NewLogParameters(table.treeId, table.prefix, table.anchors, table.signer, table.maxRange, table.maxChain)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error=%v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}

		if got, want := lp.LogId, logId; !bytes.Equal(got, want) {
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
		if got, want := lp.MaxChain, testMaxChain; got != want {
			t.Errorf("got max chain %d but wanted %d in test %q", got, want, table.description)
		}
		if got, want := lp.MaxChain, testMaxChain; got != want {
			t.Errorf("got max chain %d but wanted %d in test %q", got, want, table.description)
		}
		if got, want := len(lp.AnchorList), len(anchors); got != want {
			t.Errorf("got %d anchors but wanted %d in test %q", got, want, table.description)
		}
		if got, want := len(lp.AnchorPool.Subjects()), len(anchors); got != want {
			t.Errorf("got %d anchors in pool but wanted %d in test %q", got, want, table.description)
		}
	}
}

// TestHandlers checks that we configured all endpoints and that there are no
// unexpected ones.
func TestHandlers(t *testing.T) {
	endpoints := map[Endpoint]bool{
		EndpointAddEntry:            false,
		EndpointGetEntries:          false,
		EndpointGetSth:              false,
		EndpointGetProofByHash:      false,
		EndpointGetConsistencyProof: false,
		EndpointGetAnchors:          false,
	}
	i := NewInstance(makeTestLogParameters(t, nil), nil, testDeadline)
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
			endpoint: EndpointGetSth,
			want:     "http://example.com/test/get-sth",
		},
		{
			endpoint: EndpointGetAnchors,
			want:     "http://example.com/test/get-anchors",
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

// makeTestLogParameters makes a collection of test log parameters that
// correspond to testLogId, testTreeId, testPrefix, testMaxRange, testMaxChain,
// the anchors in testdata.TrustAnchors, testHashType, and an optional signer.
func makeTestLogParameters(t *testing.T, signer crypto.Signer) *LogParameters {
	anchors, err := x509util.NewCertificateList(testdata.TrustAnchors)
	if err != nil {
		t.Fatalf("must decode trust anchors: %v", err)
	}
	return &LogParameters{
		LogId:      testLogId,
		TreeId:     testTreeId,
		Prefix:     testPrefix,
		MaxRange:   testMaxRange,
		MaxChain:   testMaxChain,
		AnchorPool: x509util.NewCertPool(anchors),
		AnchorList: anchors,
		KeyUsage:   testExtKeyUsage,
		Signer:     signer,
		HashType:   testHashType,
	}
}
