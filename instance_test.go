package stfe

import (
	"testing"

	"crypto"
	"crypto/x509"

	"github.com/system-transparency/stfe/testdata"
	"github.com/system-transparency/stfe/x509util"
)

var (
	testHashLen     = 31
	testMaxRange    = int64(3)
	testMaxChain    = int64(3)
	testTreeId      = int64(0)
	testPrefix      = "/test"
	testHashType    = crypto.SHA256
	testExtKeyUsage = []x509.ExtKeyUsage{}
)

func makeTestLogParameters(t *testing.T, signer crypto.Signer) *LogParameters {
	anchorList, err := x509util.NewCertificateList(testdata.PemAnchors)
	if err != nil {
		t.Fatalf("must decode trust anchors: %v", err)
	}
	if got, want := len(anchorList), testdata.NumPemAnchors; got != want {
		t.Fatalf("must have %d trust anchor(s), got %d", want, got)
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
