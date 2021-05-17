package types

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	// HeaderPrefix is the start of every ST log HTTP header key
	HeaderPrefix = "stlog-"

	// New leaf
	HeaderShardHint            = HeaderPrefix + "shard_hint"
	HeaderChecksum             = HeaderPrefix + "checksum"
	HeaderSignatureOverMessage = HeaderPrefix + "signature_over_message"
	HeaderVerificationKey      = HeaderPrefix + "verification_key"
	HeaderDomainHint           = HeaderPrefix + "domain_hint"

	// Inclusion proof
	HeaderLeafHash      = HeaderPrefix + "leaf_hash"
	HeaderLeafIndex     = HeaderPrefix + "leaf_index"
	HeaderInclusionPath = HeaderPrefix + "inclusion_path"

	// Consistency proof
	HeaderNewSize         = HeaderPrefix + "new_size"
	HeaderOldSize         = HeaderPrefix + "old_size"
	HeaderConsistencyPath = HeaderPrefix + "consistency_path"

	// Range of leaves
	HeaderStartSize = HeaderPrefix + "start_size"
	HeaderEndSize   = HeaderPrefix + "end_size"

	// Tree head
	HeaderTimestamp = HeaderPrefix + "timestamp"
	HeaderTreeSize  = HeaderPrefix + "tree_size"
	HeaderRootHash  = HeaderPrefix + "root_hash"

	// Signature and signer identity
	HeaderSignature = HeaderPrefix + "signature"
	HeaderKeyHash   = HeaderPrefix + "key_hash"
)

// ToHTTP returns a signed tree-head as HTTP key-value pairs
func (sth *SignedTreeHead) ToHTTP() ([]byte, error) {
	hdr := http.Header{}
	hdr.Add(HeaderTimestamp, strconv.FormatUint(sth.Timestamp, 10))
	hdr.Add(HeaderTreeSize, strconv.FormatUint(sth.TreeSize, 10))
	hdr.Add(HeaderRootHash, hex.EncodeToString(sth.RootHash[:]))
	for _, sigident := range sth.SigIdent {
		hdr.Add(HeaderSignature, hex.EncodeToString(sigident.Signature[:]))
		hdr.Add(HeaderKeyHash, hex.EncodeToString(sigident.KeyHash[:]))
	}

	buf := bytes.NewBuffer(nil)
	if err := hdr.Write(buf); err != nil {
		return nil, fmt.Errorf("hdr.Write(): %v", err) // should not happen
	}
	return buf.Bytes(), nil
}

// ToHTTP returns a consistency proof as HTTP key-value pairs
func (p *ConsistencyProof) ToHTTP() []byte {
	return nil // TODO
}

// ToHTTP returns an inclusion proof as HTTP key-value pairs
func (p *InclusionProof) ToHTTP() []byte {
	return nil // TODO
}

// ToHTTP returns a leaf as HTTP key-value pairs
func (l *Leaf) ToHTTP() []byte {
	return nil // TODO
}

// SignedTreeHeadFromHTTP parses a signed tree head from HTTP key-value pairs
func SignedTreeHeadFromHTTP(buf []byte) (*SignedTreeHead, error) {
	hdr, err := headerFromBuf(buf)
	if err != nil {
		return nil, fmt.Errorf("headerFromBuf(): %v", err)
	}

	// TreeHead
	var sth SignedTreeHead
	sth.Timestamp, err = strconv.ParseUint(hdr.Get(HeaderTimestamp), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %v", err)
	}
	sth.TreeSize, err = strconv.ParseUint(hdr.Get(HeaderTreeSize), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid tree size: %v", err)
	}
	if err := decodeHex(hdr.Get(HeaderRootHash), sth.RootHash[:]); err != nil {
		return nil, fmt.Errorf("decodeHex(): %v", err)
	}

	// SigIdent
	signatures := hdr.Values(HeaderSignature)
	keyHashes := hdr.Values(HeaderKeyHash)
	if len(signatures) == 0 {
		return nil, fmt.Errorf("no signer")
	}
	if len(signatures) != len(keyHashes) {
		return nil, fmt.Errorf("mismatched signature-signer count")
	}
	for i := 0; i < len(signatures); i++ {
		var sigident SigIdent
		if err := decodeHex(signatures[i], sigident.Signature[:]); err != nil {
			return nil, fmt.Errorf("decodeHex(): %v", err)
		}
		if err := decodeHex(keyHashes[i], sigident.KeyHash[:]); err != nil {
			return nil, fmt.Errorf("decodeHex(): %v", err)
		}
		sth.SigIdent = append(sth.SigIdent, sigident)
	}
	return &sth, nil
}

// ConsistencyProofFromHTTP parses a consistency proof from HTTP key-value pairs
func ConsistencyProofFromHTTP(buf []byte) (*ConsistencyProof, error) {
	return nil, nil // TODO
}

// InclusionProofFromHTTP parses an inclusion proof from HTTP key-value pairs
func InclusionProofFromHTTP(buf []byte) (*InclusionProof, error) {
	return nil, nil // TODO
}

// LeavesFromHTTP parses a list of leaves from HTTP key-value pairs
func LeavesFromHTTP(buf []byte) ([]*Leaf, error) {
	return nil, nil // TODO
}

// headerFromBuf parses ST log HTTP header key-value pairs from a response body
func headerFromBuf(buf []byte) (http.Header, error) {
	hdr := http.Header{}
	lines := strings.Split(string(buf), "\r\n")
	lines = lines[:len(lines)-1] // skip the final empty line
	for _, line := range lines {
		split := strings.Split(line, ":")
		if len(split) != 2 {
			return nil, fmt.Errorf("invalid ST log HTTP header: %s", line)
		}
		if !strings.HasPrefix(strings.ToLower(split[0]), HeaderPrefix) {
			return nil, fmt.Errorf("invalid ST log HTTP header prefix: %s", line)
		}
		hdr.Add(split[0], strings.TrimSpace(split[1]))
	}
	return hdr, nil
}

// decodeHex decodes a hex-encoded string into a fixed-size output slice
func decodeHex(str string, out []byte) error {
	buf, err := hex.DecodeString(str)
	if err != nil {
		return fmt.Errorf("hex.DecodeString(): %v", err)
	}
	if len(buf) != len(out) {
		return fmt.Errorf("invalid length: %v", len(buf))
	}
	copy(out, buf)
	return nil
}
