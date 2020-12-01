package stfe

import (
	"testing"

	"crypto"
	"crypto/x509"

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

func makeTestLogParameters(t *testing.T, signer crypto.Signer) *LogParameters {
	anchorList, err := x509util.NewCertificateList(testdata.TrustAnchors)
	if err != nil {
		t.Fatalf("must decode trust anchors: %v", err)
	}
	return &LogParameters{
		LogId:      testLogId,
		TreeId:     testTreeId,
		Prefix:     testPrefix,
		MaxRange:   testMaxRange,
		MaxChain:   testMaxChain,
		AnchorPool: x509util.NewCertPool(anchorList),
		AnchorList: anchorList,
		KeyUsage:   testExtKeyUsage,
		Signer:     signer,
		HashType:   testHashType,
	}
}

func TestEndpointUrl(t *testing.T) {
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
		if got, want := table.endpoint.Url(base, prefix), table.want; got != want {
			t.Errorf("got %s but wanted %s with multiple components", got, want)
		}
		if got, want := table.endpoint.Url(base+"/"+prefix), table.want; got != want {
			t.Errorf("got %s but wanted %s with one component", got, want)
		}
	}
}
