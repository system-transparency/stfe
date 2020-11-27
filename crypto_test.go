package stfe

import (
	"bytes"
	"crypto"
	"fmt"
	"testing"

	cttestdata "github.com/google/certificate-transparency-go/trillian/testdata"
	"github.com/system-transparency/stfe/x509util"
	"github.com/system-transparency/stfe/x509util/testdata"
)

var (
	testLeaf = make([]byte, 64)
)

func TestBuildChainFromDerList(t *testing.T) {
	for _, table := range []struct {
		description string
		maxChain    int64    // including trust anchor
		anchors     []byte   // pem block
		chain       [][]byte // der list
		wantErr     bool
	}{
		{
			description: "bad chain: cannot be parsed because empty",
			maxChain:    3,
			anchors:     testdata.RootCertificate,
			wantErr:     true,
		},
		{
			description: "bad chain: no path from end-entity to intermediate",
			maxChain:    3,
			anchors:     testdata.RootCertificate2,
			chain:       mustMakeDerList(t, testdata.ChainBadIntermediate)[:2],
			wantErr:     true,
		},
		{
			description: "bad chain: no path from intermediate to root",
			maxChain:    3,
			anchors:     testdata.RootCertificate2,
			chain:       mustMakeDerList(t, testdata.IntermediateChain),
			wantErr:     true,
		},
		{
			description: "bad chain: end-entity certificate expired",
			maxChain:    3,
			anchors:     testdata.RootCertificate,
			chain:       mustMakeDerList(t, testdata.ExpiredChain),
		},
		{
			description: "bad chain: too large",
			maxChain:    2,
			anchors:     testdata.RootCertificate,
			chain:       mustMakeDerList(t, testdata.IntermediateChain),
			wantErr:     true,
		},
		{
			description: "ok chain: one explicit trust anchor",
			maxChain:    3,
			anchors:     testdata.RootCertificate,
			chain:       mustMakeDerList(t, testdata.RootChain),
		},
		{
			description: "ok chain: unnecessary certificates are ignored",
			maxChain:    3,
			anchors:     testdata.RootCertificate,
			chain:       append(mustMakeDerList(t, testdata.IntermediateChain), mustMakeDerList(t, testdata.IntermediateChain2)...),
		},
		{
			description: "ok chain: multiple anchors but one valid path",
			maxChain:    3,
			anchors:     testdata.TrustAnchors,
			chain:       mustMakeDerList(t, testdata.IntermediateChain),
		},
		// Note that the underlying verify function also checks name constraints
		// and extended key usages.  Not relied upon atm, so not tested.
	} {
		anchorList, err := x509util.NewCertificateList(table.anchors)
		if err != nil {
			t.Fatalf("must parse trust anchors: %v", err)
		}
		lp := &LogParameters{
			LogId:      testLogId,
			TreeId:     testTreeId,
			Prefix:     testPrefix,
			MaxRange:   testMaxRange,
			MaxChain:   table.maxChain,
			AnchorPool: x509util.NewCertPool(anchorList),
			AnchorList: anchorList,
			KeyUsage:   testExtKeyUsage,
			Signer:     nil,
			HashType:   testHashType,
		}
		_, err = lp.buildChainFromDerList(table.chain)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error=%v but wanted %v in test %q: %v", got, want, table.description, err)
		}
	}
}

// TODO: TestVerifySignature
func TestVerifySignature(t *testing.T) {
}

// TestGenV1Sdi tests that a signature failure works as expected, and that
// the issued SDI (if any) is populated correctly.
func TestGenV1Sdi(t *testing.T) {
	for _, table := range []struct {
		description string
		leaf        []byte
		signer      crypto.Signer
		wantErr     bool
	}{
		{
			description: "signature failure",
			leaf:        testLeaf,
			signer:      cttestdata.NewSignerWithErr(nil, fmt.Errorf("signer failed")),
			wantErr:     true,
		},
		{
			description: "all ok",
			leaf:        testLeaf,
			signer:      cttestdata.NewSignerWithFixedSig(nil, testSignature),
		},
	} {
		item, err := makeTestLogParameters(t, table.signer).genV1Sdi(table.leaf)
		if err != nil && !table.wantErr {
			t.Errorf("signing failed in test %q: %v", table.description, err)
		} else if err == nil && table.wantErr {
			t.Errorf("signing succeeded but wanted failure in test %q", table.description)
		}
		if err != nil || table.wantErr {
			continue
		}
		if want, got := item.Format, StFormatSignedDebugInfoV1; got != want {
			t.Errorf("got format %s, wanted %s in test %q", got, want, table.description)
			continue
		}

		sdi := item.SignedDebugInfoV1
		if got, want := sdi.LogId, testLogId; !bytes.Equal(got, want) {
			t.Errorf("got logId %X, wanted %X in test %q", got, want, table.description)
		}
		if got, want := sdi.Message, []byte("reserved"); !bytes.Equal(got, want) {
			t.Errorf("got message %s, wanted %s in test %q", got, want, table.description)
		}
		if got, want := sdi.Signature, testSignature; !bytes.Equal(got, want) {
			t.Errorf("got signature %X, wanted %X in test %q", got, want, table.description)
		}
	}
}

// TestGenV1Sth tests that a signature failure works as expected, and that
// the issued STH (if any) is populated correctly.
func TestGenV1Sth(t *testing.T) {
	th := NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash))
	for _, table := range []struct {
		description string
		th          *TreeHeadV1
		signer      crypto.Signer
		wantErr     bool
	}{
		{
			description: "marshal failure",
			th:          NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, nil)),
			wantErr:     true,
		},
		{
			description: "signature failure",
			th:          th,
			signer:      cttestdata.NewSignerWithErr(nil, fmt.Errorf("signer failed")),
			wantErr:     true,
		},
		{
			description: "all ok",
			th:          th,
			signer:      cttestdata.NewSignerWithFixedSig(nil, testSignature),
		},
	} {
		item, err := makeTestLogParameters(t, table.signer).genV1Sth(table.th)
		if err != nil && !table.wantErr {
			t.Errorf("signing failed in test %q: %v", table.description, err)
		} else if err == nil && table.wantErr {
			t.Errorf("signing succeeded but wanted failure in test %q", table.description)
		}
		if err != nil || table.wantErr {
			continue
		}
		if want, got := item.Format, StFormatSignedTreeHeadV1; got != want {
			t.Errorf("got format %s, wanted %s in test %q", got, want, table.description)
			continue
		}

		sth := item.SignedTreeHeadV1
		if got, want := sth.LogId, testLogId; !bytes.Equal(got, want) {
			t.Errorf("got logId %X, wanted %X in test %q", got, want, table.description)
		}
		if got, want := sth.Signature, testSignature; !bytes.Equal(got, want) {
			t.Errorf("got signature %X, wanted %X in test %q", got, want, table.description)
		}
		if got, want := sth.TreeHead.Timestamp, th.Timestamp; got != want {
			t.Errorf("got timestamp %d, wanted %d in test %q", got, want, table.description)
		}
		if got, want := sth.TreeHead.TreeSize, th.TreeSize; got != want {
			t.Errorf("got tree size %d, wanted %d in test %q", got, want, table.description)
		}
		if got, want := sth.TreeHead.RootHash.Data, th.RootHash.Data; !bytes.Equal(got, want) {
			t.Errorf("got root hash %X, wanted %X in test %q", got, want, table.description)
		}
		if sth.TreeHead.Extension != nil {
			t.Errorf("got extensions %X, wanted nil in test %q", sth.TreeHead.Extension, table.description)
		}
	}
}

// TODO: test that metrics are updated correctly?

// mustMakeDerList must parse a PEM-encoded list of certificates to DER
func mustMakeDerList(t *testing.T, pem []byte) [][]byte {
	certs, err := x509util.NewCertificateList(pem)
	if err != nil {
		t.Fatalf("must parse pem-encoded certificates: %v", err)
	}

	list := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		list = append(list, cert.Raw)
	}
	return list
}
