package stfe

import (
	"crypto"
	"fmt"
	"reflect"
	"testing"

	cttestdata "github.com/google/certificate-transparency-go/trillian/testdata"
	"github.com/system-transparency/stfe/testdata"
	"github.com/system-transparency/stfe/types"
)

// newLogParameters must create new log parameters with an optional log signer
// based on the parameters in "github.com/system-transparency/stfe/testdata".
// The log's namespace is initialized with testdata.LogEd25519Vk, the submmiter
// namespace list is initialized with testdata.SubmmiterEd25519, and the witness
// namespace list is initialized with testdata.WitnessEd25519Vk.  The log's
// submitter and witness policies are set to reject unregistered namespace.
func newLogParameters(t *testing.T, signer crypto.Signer) *LogParameters {
	t.Helper()
	logId := testdata.NewNamespace(t, testdata.Ed25519VkLog)
	witnessPool := testdata.NewNamespacePool(t, []*types.Namespace{
		testdata.NewNamespace(t, testdata.Ed25519VkWitness),
	})
	submitPool := testdata.NewNamespacePool(t, []*types.Namespace{
		testdata.NewNamespace(t, testdata.Ed25519VkSubmitter),
	})
	lp, err := NewLogParameters(signer, logId, testdata.TreeId, testdata.Prefix, submitPool, witnessPool, testdata.MaxRange, testdata.Interval, testdata.Deadline, true, true)
	if err != nil {
		t.Fatalf("must create new log parameters: %v", err)
	}
	return lp
}

func TestNewLogParameters(t *testing.T) {
	for _, table := range []struct {
		description string
		logId       *types.Namespace
		wantErr     bool
	}{
		{
			description: "invalid: cannot marshal log id",
			logId: &types.Namespace{
				Format: types.NamespaceFormatReserved,
			},
			wantErr: true,
		},
		{
			description: "valid",
			logId:       testdata.NewNamespace(t, testdata.Ed25519VkLog),
		},
	} {
		_, err := NewLogParameters(nil, table.logId, testdata.TreeId, testdata.Prefix, nil, nil, testdata.MaxRange, testdata.Interval, testdata.Deadline, true, true)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
	}
}

func TestSignTreeHeadV1(t *testing.T) {
	for _, table := range []struct {
		description string
		th          *types.TreeHeadV1
		signer      crypto.Signer
		wantErr     bool
		wantSth     *types.StItem
	}{
		{
			description: "invalid: marshal failure",
			th:          types.NewTreeHeadV1(testdata.Timestamp, testdata.TreeSize, nil, testdata.Extension),
			wantErr:     true,
		},
		{
			description: "invalid: signature failure",
			th:          types.NewTreeHeadV1(testdata.Timestamp, testdata.TreeSize, testdata.NodeHash, testdata.Extension),
			signer:      cttestdata.NewSignerWithErr(nil, fmt.Errorf("signer failed")),
			wantErr:     true,
		},
		{
			description: "valid",
			th:          testdata.DefaultTh(t),
			signer:      cttestdata.NewSignerWithFixedSig(nil, testdata.Signature),
			wantSth:     testdata.DefaultSth(t, testdata.Ed25519VkLog),
		},
	} {
		sth, err := newLogParameters(t, table.signer).SignTreeHeadV1(table.th)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}

		if got, want := sth, table.wantSth; !reflect.DeepEqual(got, want) {
			t.Errorf("got \n%v\n\tbut wanted\n%v\n\tin test %q", got, want, table.description)
		}
	}
}
