package stfe

import (
	"bytes"
	"crypto"
	"fmt"
	"testing"

	cttestdata "github.com/google/certificate-transparency-go/trillian/testdata"
)

var (
	testLeaf = make([]byte, 64)
)

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
