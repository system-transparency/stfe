package testdata

import (
	"bytes"
	"testing"
	"time"

	"crypto/ed25519"

	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"github.com/system-transparency/stfe/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	Ed25519VkLog  = [32]byte{}
	Ed25519VkLog2 = [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	Ed25519VkLog3 = [32]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	//Ed25519VkWitness   = [32]byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
	//	Ed25519VkWitness2  = [32]byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4}
	Ed25519VkWitness3 = [32]byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5}
	//Ed25519VkSubmitter = [32]byte{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6}

	TreeId   = int64(0)
	Prefix   = "test"
	MaxRange = int64(3)
	Interval = time.Second * 10
	Deadline = time.Second * 5

	Timestamp  = uint64(0)
	TreeSize   = uint64(0)
	Extension  = make([]byte, 0)
	NodeHash   = make([]byte, 32)
	Signature  = make([]byte, 64)
	Identifier = []byte("foobar-1.2.3")
	Checksum   = make([]byte, 32)
	Index      = int64(0)
	HashPath   = [][]byte{
		NodeHash,
	}
	NodePath = []types.NodeHash{
		types.NodeHash{NodeHash},
	}
	LeafHash = [32]byte{}

	// TODO: make these unique and load more pretty maybe
	Ed25519SkWitness = [64]byte{230, 122, 195, 152, 194, 195, 147, 153, 80, 120, 153, 79, 102, 27, 52, 187, 136, 218, 150, 234, 107, 9, 167, 4, 92, 21, 11, 113, 42, 29, 129, 69, 75, 60, 249, 150, 229, 93, 75, 32, 103, 126, 244, 37, 53, 182, 68, 82, 249, 109, 49, 94, 10, 19, 146, 244, 58, 191, 169, 107, 78, 37, 45, 210}
	Ed25519VkWitness = [32]byte{75, 60, 249, 150, 229, 93, 75, 32, 103, 126, 244, 37, 53, 182, 68, 82, 249, 109, 49, 94, 10, 19, 146, 244, 58, 191, 169, 107, 78, 37, 45, 210}

	Ed25519SkWitness2 = [64]byte{98, 65, 92, 117, 33, 167, 138, 36, 252, 147, 87, 173, 44, 62, 17, 66, 126, 70, 218, 87, 91, 148, 64, 194, 241, 248, 62, 90, 140, 122, 234, 76, 144, 6, 250, 185, 37, 217, 77, 201, 180, 42, 81, 37, 165, 27, 22, 32, 25, 8, 156, 228, 78, 207, 208, 18, 91, 77, 189, 51, 112, 31, 237, 6}
	Ed25519VkWitness2 = [32]byte{144, 6, 250, 185, 37, 217, 77, 201, 180, 42, 81, 37, 165, 27, 22, 32, 25, 8, 156, 228, 78, 207, 208, 18, 91, 77, 189, 51, 112, 31, 237, 6}

	Ed25519SkSubmitter  = [64]byte{230, 122, 195, 152, 194, 195, 147, 153, 80, 120, 153, 79, 102, 27, 52, 187, 136, 218, 150, 234, 107, 9, 167, 4, 92, 21, 11, 113, 42, 29, 129, 69, 75, 60, 249, 150, 229, 93, 75, 32, 103, 126, 244, 37, 53, 182, 68, 82, 249, 109, 49, 94, 10, 19, 146, 244, 58, 191, 169, 107, 78, 37, 45, 210}
	Ed25519VkSubmitter  = [32]byte{75, 60, 249, 150, 229, 93, 75, 32, 103, 126, 244, 37, 53, 182, 68, 82, 249, 109, 49, 94, 10, 19, 146, 244, 58, 191, 169, 107, 78, 37, 45, 210}
	Ed25519SkSubmitter2 = [64]byte{98, 65, 92, 117, 33, 167, 138, 36, 252, 147, 87, 173, 44, 62, 17, 66, 126, 70, 218, 87, 91, 148, 64, 194, 241, 248, 62, 90, 140, 122, 234, 76, 144, 6, 250, 185, 37, 217, 77, 201, 180, 42, 81, 37, 165, 27, 22, 32, 25, 8, 156, 228, 78, 207, 208, 18, 91, 77, 189, 51, 112, 31, 237, 6}
	Ed25519VkSubmitter2 = [32]byte{144, 6, 250, 185, 37, 217, 77, 201, 180, 42, 81, 37, 165, 27, 22, 32, 25, 8, 156, 228, 78, 207, 208, 18, 91, 77, 189, 51, 112, 31, 237, 6}
)

// TODO: reorder and docdoc where need be
//
// Helpers that must create default values for different STFE types
//

func DefaultCosth(t *testing.T, logVk [32]byte, witVk [][32]byte) *types.StItem {
	t.Helper()
	cosigs := make([]types.SignatureV1, 0)
	for _, vk := range witVk {
		cosigs = append(cosigs, types.SignatureV1{*NewNamespace(t, vk), Signature})
	}
	return types.NewCosignedTreeHeadV1(DefaultSth(t, logVk).SignedTreeHeadV1, cosigs)
}

func DefaultSth(t *testing.T, vk [32]byte) *types.StItem {
	t.Helper()
	return types.NewSignedTreeHeadV1(DefaultTh(t), DefaultSig(t, vk))
}

func DefaultSignedChecksum(t *testing.T, vk [32]byte) *types.StItem {
	t.Helper()
	return types.NewSignedChecksumV1(DefaultChecksum(t), DefaultSig(t, vk))
}

func DefaultTh(t *testing.T) *types.TreeHeadV1 {
	t.Helper()
	return types.NewTreeHeadV1(Timestamp, TreeSize, NodeHash, Extension)
}

func DefaultSig(t *testing.T, vk [32]byte) *types.SignatureV1 {
	t.Helper()
	return &types.SignatureV1{*NewNamespace(t, vk), Signature}
}

func DefaultChecksum(t *testing.T) *types.ChecksumV1 {
	t.Helper()
	return &types.ChecksumV1{Identifier, Checksum}
}

func AddCosignatureBuffer(t *testing.T, sth *types.StItem, sk *[64]byte, vk *[32]byte) *bytes.Buffer {
	t.Helper()
	var cosigs []types.SignatureV1
	if vk != nil {
		cosigs = []types.SignatureV1{
			types.SignatureV1{
				Namespace: *NewNamespace(t, *vk),
				Signature: ed25519.Sign(ed25519.PrivateKey((*sk)[:]), marshal(t, *sth.SignedTreeHeadV1)),
			},
		}
	}
	return bytes.NewBuffer(marshal(t, *types.NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, cosigs)))
}

func AddSignedChecksumBuffer(t *testing.T, sk [64]byte, vk [32]byte) *bytes.Buffer {
	t.Helper()
	data := DefaultChecksum(t)
	return bytes.NewBuffer(marshal(t, *types.NewSignedChecksumV1(
		data,
		&types.SignatureV1{
			Namespace: *NewNamespace(t, vk),
			Signature: ed25519.Sign(ed25519.PrivateKey(sk[:]), marshal(t, *data)),
		},
	)))
}

func NewNamespacePool(t *testing.T, namespaces []*types.Namespace) *types.NamespacePool {
	pool, err := types.NewNamespacePool(namespaces)
	if err != nil {
		t.Fatalf("must make namespace pool: %v", err)
	}
	return pool
}

func NewNamespace(t *testing.T, vk [32]byte) *types.Namespace {
	namespace, err := types.NewNamespaceEd25519V1(vk[:])
	if err != nil {
		t.Fatalf("must make Ed25519V1 namespace: %v", err)
	}
	return namespace
}

//
// Helpers that must create default values for different Trillian types
//

// DefaultTLr creates a default Trillian log root
func DefaultTLr(t *testing.T) *ttypes.LogRootV1 {
	t.Helper()
	return Tlr(t, TreeSize, Timestamp, NodeHash)
}

// Tlr creates a Trillian log root
func Tlr(t *testing.T, size, timestamp uint64, hash []byte) *ttypes.LogRootV1 {
	t.Helper()
	return &ttypes.LogRootV1{
		TreeSize:       size,
		RootHash:       hash,
		TimestampNanos: timestamp,
		Revision:       0,   // not used by stfe
		Metadata:       nil, // not used by stfe
	}
}

// DefaultTSlr creates a default Trillian signed log root
func DefaultTSlr(t *testing.T) *trillian.GetLatestSignedLogRootResponse {
	t.Helper()
	return Tslr(t, DefaultTLr(t))
}

// Tslr creates a Trillian signed log root
func Tslr(t *testing.T, lr *ttypes.LogRootV1) *trillian.GetLatestSignedLogRootResponse {
	t.Helper()
	b, err := lr.MarshalBinary()
	if err != nil {
		t.Fatalf("must marshal Trillian log root: %v", err)
	}
	return &trillian.GetLatestSignedLogRootResponse{
		SignedLogRoot: &trillian.SignedLogRoot{
			KeyHint:          nil, // not used by stfe
			LogRoot:          b,
			LogRootSignature: nil, // not used by stfe
		},
		Proof: nil, // not used by stfe
	}
}

// DefaultTQlr creates a default Trillian queue leaf response
func DefaultTQlr(t *testing.T, withDupCode bool) *trillian.QueueLeafResponse {
	t.Helper()
	s := status.New(codes.OK, "ok").Proto()
	if withDupCode {
		s = status.New(codes.AlreadyExists, "duplicate").Proto()
	}
	return &trillian.QueueLeafResponse{
		QueuedLeaf: &trillian.QueuedLogLeaf{
			Leaf: &trillian.LogLeaf{
				MerkleLeafHash:   nil, // not used by stfe
				LeafValue:        marshal(t, *DefaultSignedChecksum(t, Ed25519VkSubmitter)),
				ExtraData:        nil, // not used by stfe
				LeafIndex:        0,   // not applicable (log is not pre-ordered)
				LeafIdentityHash: nil, // not used by stfe
			},
			Status: s,
		},
	}
}

// DefaultTglbrr creates a default Trillian get leaves by range response
func DefaultTGlbrr(t *testing.T, start, end int64) *trillian.GetLeavesByRangeResponse {
	t.Helper()
	leaves := make([]*trillian.LogLeaf, 0, end-start+1)
	for i, n := start, end+1; i < n; i++ {
		leaves = append(leaves, &trillian.LogLeaf{
			MerkleLeafHash:   nil, // not usedb y stfe
			LeafValue:        marshal(t, *DefaultSignedChecksum(t, Ed25519VkSubmitter)),
			ExtraData:        nil, // not used by stfe
			LeafIndex:        i,
			LeafIdentityHash: nil, // not used by stfe
		})
	}
	return &trillian.GetLeavesByRangeResponse{
		Leaves:        leaves,
		SignedLogRoot: Tslr(t, Tlr(t, uint64(end)+1, Timestamp, NodeHash)).SignedLogRoot,
	}
}

func DefaultStItemList(t *testing.T, start, end uint64) *types.StItemList {
	items := make([]types.StItem, 0, end-start+1)
	for i, n := start, end+1; i < n; i++ {
		items = append(items, *DefaultSignedChecksum(t, Ed25519VkSubmitter))
	}
	return &types.StItemList{items}
}

// DefaultTGipbhr creates a default Trillian get inclusion proof by hash response
func DefaultTGipbhr(t *testing.T) *trillian.GetInclusionProofByHashResponse {
	t.Helper()
	return &trillian.GetInclusionProofByHashResponse{
		Proof: []*trillian.Proof{
			&trillian.Proof{
				LeafIndex: Index,
				Hashes:    HashPath,
			},
		},
		SignedLogRoot: nil, // not used by stfe
	}
}

func DefaultInclusionProof(t *testing.T, size uint64) *types.StItem {
	return types.NewInclusionProofV1(NewNamespace(t, Ed25519VkLog), size, uint64(Index), NodePath)
}

// DefaultTGcpr creates a default Trillian get consistency proof response
func DefaultTGcpr(t *testing.T) *trillian.GetConsistencyProofResponse {
	t.Helper()
	return &trillian.GetConsistencyProofResponse{
		Proof: &trillian.Proof{
			LeafIndex: 0, // not applicable for consistency proofs
			Hashes:    HashPath,
		},
		SignedLogRoot: nil, // not used by stfe
	}
}

func DefaultConsistencyProof(t *testing.T, first, second uint64) *types.StItem {
	return types.NewConsistencyProofV1(NewNamespace(t, Ed25519VkLog), first, second, NodePath)
}

//
// Other helpers
//

func Fingerprint(t *testing.T, namespace *types.Namespace) [types.NamespaceFingerprintSize]byte {
	fpr, err := namespace.Fingerprint()
	if err != nil {
		t.Fatalf("must have namespace fingerprint: %v", err)
	}
	return *fpr
}

func marshal(t *testing.T, i interface{}) []byte {
	b, err := types.Marshal(i)
	if err != nil {
		t.Fatalf("must marshal interface: %v", err)
	}
	return b
}
