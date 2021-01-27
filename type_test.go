package stfe

import (
	"testing"

	"github.com/system-transparency/stfe/namespace/testdata"
)

// TestEncDecStItem tests that valid StItems can be (un)marshaled, and that
// invalid ones in fact fail.
//
// Note: max limits for inclusion and consistency proofs are not tested.
// Note: TreeHeadV1 extensions are not tested (not used by stfe)
func TestEncDecStItem(t *testing.T) {
	logIdSize := 35
	signatureMin := 1
	signatureMax := 65535
	messageMax := 65535
	nodeHashMin := 32
	nodeHashMax := 255
	packageMin := 1
	packageMax := 255
	checksumMin := 1
	checksumMax := 64
	for _, table := range []struct {
		description string
		item        *StItem
		wantErr     bool
	}{
		// signed_tree_head_v1
		{
			description: "too short log id",
			item:        NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), make([]byte, logIdSize-1), testSignature),
			wantErr:     true,
		},
		{
			description: "too large log id",
			item:        NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), make([]byte, logIdSize+1), testSignature),
			wantErr:     true,
		},
		{
			description: "ok log id: min and max",
			item:        NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), testLogId, testSignature),
		},
		{
			description: "too short signature",
			item:        NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), testLogId, make([]byte, signatureMin-1)),
			wantErr:     true,
		},
		{
			description: "too large signature",
			item:        NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), testLogId, make([]byte, signatureMax+1)),
			wantErr:     true,
		},
		{
			description: "ok signature: min",
			item:        NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), testLogId, make([]byte, signatureMin)),
		},
		{
			description: "ok signature: max",
			item:        NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), testLogId, make([]byte, signatureMax)),
		},
		{
			description: "too short root hash",
			item:        NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, make([]byte, nodeHashMin-1))), testLogId, testSignature),
			wantErr:     true,
		},
		{
			description: "too large root hash",
			item:        NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, make([]byte, nodeHashMax+1))), testLogId, testSignature),
			wantErr:     true,
		},
		{
			description: "ok root hash: min",
			item:        NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, make([]byte, nodeHashMin))), testLogId, testSignature),
		},
		{
			description: "ok root hash: min",
			item:        NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, make([]byte, nodeHashMax))), testLogId, testSignature),
		},
		// signed_debug_info_v1
		{
			description: "too short log id",
			item:        NewSignedDebugInfoV1(make([]byte, logIdSize-1), testMessage, testSignature),
			wantErr:     true,
		},
		{
			description: "too large log id",
			item:        NewSignedDebugInfoV1(make([]byte, logIdSize+1), testMessage, testSignature),
			wantErr:     true,
		},
		{
			description: "ok log id: min and max",
			item:        NewSignedDebugInfoV1(testLogId, testMessage, testSignature),
		},
		{
			description: "too large message",
			item:        NewSignedDebugInfoV1(testLogId, make([]byte, messageMax+1), testSignature),
			wantErr:     true,
		},
		{
			description: "ok message: max",
			item:        NewSignedDebugInfoV1(testLogId, make([]byte, messageMax), testSignature),
		},
		{
			description: "too short signature",
			item:        NewSignedDebugInfoV1(testLogId, testMessage, make([]byte, signatureMin-1)),
			wantErr:     true,
		},
		{
			description: "too large signature",
			item:        NewSignedDebugInfoV1(testLogId, testMessage, make([]byte, signatureMax+1)),
			wantErr:     true,
		},
		{
			description: "ok signature: min",
			item:        NewSignedDebugInfoV1(testLogId, testMessage, make([]byte, signatureMin)),
		},
		{
			description: "ok signature: max",
			item:        NewSignedDebugInfoV1(testLogId, testMessage, make([]byte, signatureMax)),
		},
		// consistency_proof_v1
		{
			description: "too short log id",
			item:        NewConsistencyProofV1(make([]byte, logIdSize-1), testTreeSize, testTreeSizeLarger, testProof),
			wantErr:     true,
		},
		{
			description: "too large log id",
			item:        NewConsistencyProofV1(make([]byte, logIdSize+1), testTreeSize, testTreeSizeLarger, testProof),
			wantErr:     true,
		},
		{
			description: "ok log id: min and max",
			item:        NewConsistencyProofV1(testLogId, testTreeSize, testTreeSizeLarger, testProof),
		},
		{
			description: "too small node hash in proof",
			item:        NewConsistencyProofV1(testLogId, testTreeSize, testTreeSizeLarger, [][]byte{make([]byte, nodeHashMin-1)}),
			wantErr:     true,
		},
		{
			description: "too large node hash in proof",
			item:        NewConsistencyProofV1(testLogId, testTreeSize, testTreeSizeLarger, [][]byte{make([]byte, nodeHashMax+1)}),
			wantErr:     true,
		},
		{
			description: "ok proof: min node hash",
			item:        NewConsistencyProofV1(testLogId, testTreeSize, testTreeSizeLarger, [][]byte{make([]byte, nodeHashMin)}),
		},
		{
			description: "ok proof: max node hash",
			item:        NewConsistencyProofV1(testLogId, testTreeSize, testTreeSizeLarger, [][]byte{make([]byte, nodeHashMin)}),
		},
		{
			description: "ok proof: empty",
			item:        NewConsistencyProofV1(testLogId, testTreeSize, testTreeSizeLarger, [][]byte{}),
		},
		// inclusion_proof_v1
		{
			description: "too short log id",
			item:        NewInclusionProofV1(make([]byte, logIdSize-1), testTreeSize, testIndex, testProof),
			wantErr:     true,
		},
		{
			description: "too large log id",
			item:        NewInclusionProofV1(make([]byte, logIdSize+1), testTreeSize, testIndex, testProof),
			wantErr:     true,
		},
		{
			description: "ok log id: min and max",
			item:        NewInclusionProofV1(testLogId, testTreeSize, testIndex, testProof),
		},
		{
			description: "too short node hash in proof",
			item:        NewInclusionProofV1(testLogId, testTreeSize, testIndex, [][]byte{make([]byte, nodeHashMin-1)}),
			wantErr:     true,
		},
		{
			description: "too large node hash in proof",
			item:        NewInclusionProofV1(testLogId, testTreeSize, testIndex, [][]byte{make([]byte, nodeHashMax+1)}),
			wantErr:     true,
		},
		{
			description: "ok proof: min node hash",
			item:        NewInclusionProofV1(testLogId, testTreeSize, testIndex, [][]byte{make([]byte, nodeHashMin)}),
		},
		{
			description: "ok proof: max node hash",
			item:        NewInclusionProofV1(testLogId, testTreeSize, testIndex, [][]byte{make([]byte, nodeHashMax)}),
		},
		{
			description: "ok proof: empty",
			item:        NewInclusionProofV1(testLogId, testTreeSize, testIndex, [][]byte{}),
		},
		// checksum_v1
		{
			description: "too short package",
			item:        NewChecksumV1(make([]byte, packageMin-1), testChecksum, mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)),
			wantErr:     true,
		},
		{
			description: "too large package",
			item:        NewChecksumV1(make([]byte, packageMax+1), testChecksum, mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)),
			wantErr:     true,
		},
		{
			description: "ok package: min",
			item:        NewChecksumV1(make([]byte, packageMin), testChecksum, mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)),
		},
		{
			description: "ok package: max",
			item:        NewChecksumV1(make([]byte, packageMax), testChecksum, mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)),
		},
		{
			description: "too short checksum",
			item:        NewChecksumV1(testPackage, make([]byte, checksumMin-1), mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)),
			wantErr:     true,
		},
		{
			description: "too large checksum",
			item:        NewChecksumV1(testPackage, make([]byte, checksumMax+1), mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)),
			wantErr:     true,
		}, // namespace (un)marshal is already tested in its own package (skip)
		{
			description: "ok checksum: min",
			item:        NewChecksumV1(testPackage, make([]byte, checksumMin), mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)),
		},
		{
			description: "ok checksum: max",
			item:        NewChecksumV1(testPackage, make([]byte, checksumMax), mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)),
		},
	} {
		b, err := table.item.MarshalB64()
		if err != nil && !table.wantErr {
			t.Errorf("failed marshaling StItem(%s) in test %q: %v", table.item.Format, table.description, err)
		} else if err == nil && table.wantErr {
			t.Errorf("succeeded marshaling StItem(%s) in test %q but want failure", table.item.Format, table.description)
		}
		if err != nil || table.wantErr {
			continue // nothing to unmarshal
		}

		var item StItem
		if err := item.UnmarshalB64(b); err != nil {
			t.Errorf("failed unmarshaling StItem(%s) in test %q: %v", table.item.Format, table.description, err)
		}
	}
}

// TestTreeHeadMarshal tests that valid tree heads can be marshaled and that
// invalid ones cannot.
//
// Note: TreeHeadV1 extensions are not tested (not used by stfe)
func TestTreeHeadMarshal(t *testing.T) {
	nodeHashMin := 32
	nodeHashMax := 255
	for _, table := range []struct {
		description string
		th          *TreeHeadV1
		wantErr     bool
	}{
		{
			description: "too short root hash",
			th:          NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, make([]byte, nodeHashMin-1))),
			wantErr:     true,
		},
		{
			description: "too large root hash",
			th:          NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, make([]byte, nodeHashMax+1))),
			wantErr:     true,
		},
		{
			description: "ok tree head: min node hash",
			th:          NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, make([]byte, nodeHashMin))),
		},
		{
			description: "ok tree head: max node hash",
			th:          NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, make([]byte, nodeHashMax))),
		},
	} {
		if _, err := table.th.Marshal(); err != nil && !table.wantErr {
			t.Errorf("failed marshaling in test %q: %v", table.description, err)
		} else if err == nil && table.wantErr {
			t.Errorf("succeeded marshaling but wanted error in test %q: %v", table.description, err)
		}
	}
}

// TestStItemUnmarshal tests that invalid ST items cannot be unmarshaled
func TestStItemUnmarshalFailure(t *testing.T) {
	b, err := NewChecksumV1(testPackage, testChecksum, mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)).Marshal()
	if err != nil {
		t.Errorf("must marshal ChecksumV1 StItem: %v", err)
		return
	}

	var checksum StItem
	if err := checksum.Unmarshal(append(b[:], []byte{0}...)); err == nil {
		t.Errorf("succeeded unmarshaling but wanted error: one extra byte")
	}
	if err := checksum.Unmarshal(append(b[:], b[:]...)); err == nil {
		t.Errorf("succeeded unmarshaling but wanted error: one extra b")
	}
	if err := checksum.Unmarshal([]byte{0}); err == nil {
		t.Errorf("succeeded unmarshaling but wanted error: just a single byte")
	}

	b[0] = byte(len(testPackage)) + 1 // will mess up the first length specifier
	if err := checksum.Unmarshal(b); err == nil {
		t.Errorf("succeeded unmarshaling but wanted error: bad length")
	}

	if err := checksum.UnmarshalB64("@" + b64(b[1:])); err == nil {
		t.Errorf("succeded unmarshaling base64 but wanted error: bad byte")
	}
}
