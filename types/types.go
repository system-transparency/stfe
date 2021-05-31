package types

import (
	"crypto/ed25519"
	"crypto/sha256"
)

const (
	HashSize            = sha256.Size
	SignatureSize       = ed25519.SignatureSize
	VerificationKeySize = ed25519.PublicKeySize
)

// Leaf is the log's Merkle tree leaf.
//
// Ref: https://github.com/system-transparency/stfe/blob/design/doc/api.md#merkle-tree-leaf
type Leaf struct {
	Message
	SigIdent
}

// Message is composed of a shard hint and a checksum.  The submitter selects
// these values to fit the log's shard interval and the opaque data in question.
type Message struct {
	ShardHint uint64
	Checksum  *[HashSize]byte
}

// SigIdent is composed of a signature-signer pair.  The signature is computed
// over the Trunnel-serialized leaf message.  KeyHash identifies the signer.
type SigIdent struct {
	Signature *[SignatureSize]byte
	KeyHash   *[HashSize]byte
}

// SignedTreeHead is composed of a tree head and a list of signature-signer
// pairs.  Each signature is computed over the Trunnel-serialized tree head.
//
// Ref: https://github.com/system-transparency/stfe/blob/design/doc/api.md#get-tree-head-cosigned
// Ref: https://github.com/system-transparency/stfe/blob/design/doc/api.md#get-tree-head-to-sign
// Ref: https://github.com/system-transparency/stfe/blob/design/doc/api.md#get-tree-head-latest
type SignedTreeHead struct {
	TreeHead
	SigIdent []*SigIdent
}

// TreeHead is the log's tree head.
//
// Ref: https://github.com/system-transparency/stfe/blob/design/doc/api.md#merkle-tree-head
type TreeHead struct {
	Timestamp uint64
	TreeSize  uint64
	RootHash  *[HashSize]byte
}

// ConsistencyProof is a consistency proof that proves the log's append-only
// property.
//
// Ref: https://github.com/system-transparency/stfe/blob/design/doc/api.md#get-consistency-proof
type ConsistencyProof struct {
	NewSize uint64
	OldSize uint64
	Path    []*[HashSize]byte
}

// InclusionProof is an inclusion proof that proves a leaf is included in the
// log.
//
// Ref: https://github.com/system-transparency/stfe/blob/design/doc/api.md#get-proof-by-hash
type InclusionProof struct {
	TreeSize  uint64
	LeafIndex uint64
	Path      []*[HashSize]byte
}

// LeafList is a list of leaves
type LeafList []*Leaf

// ConsistencyProofRequest is a get-consistency-proof request
//
// Ref: https://github.com/system-transparency/stfe/blob/design/doc/api.md#get-consistency-proof
type ConsistencyProofRequest struct {
	NewSize uint64
	OldSize uint64
}

// InclusionProofRequest is a get-proof-by-hash request
//
// Ref: https://github.com/system-transparency/stfe/blob/design/doc/api.md#get-proof-by-hash
type InclusionProofRequest struct {
	LeafHash *[HashSize]byte
	TreeSize uint64
}

// LeavesRequest is a get-leaves request
//
// Ref: https://github.com/system-transparency/stfe/blob/design/doc/api.md#get-leaves
type LeavesRequest struct {
	StartSize uint64
	EndSize   uint64
}

// LeafRequest is an add-leaf request
//
// Ref: https://github.com/system-transparency/stfe/blob/design/doc/api.md#add-leaf
type LeafRequest struct {
	Message
	Signature       *[SignatureSize]byte
	VerificationKey *[VerificationKeySize]byte
	DomainHint      string
}

// CosignatureRequest is an add-cosignature request
//
// Ref: https://github.com/system-transparency/stfe/blob/design/doc/api.md#add-cosignature
type CosignatureRequest struct {
	SigIdent
}
