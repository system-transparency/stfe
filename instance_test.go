package stfe

import (
	"testing"

	"crypto"
	"crypto/x509"

	"github.com/system-transparency/stfe/testdata"
	"github.com/system-transparency/stfe/x509util"
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
	}
}
