package stfe

import (
	"fmt"

	"crypto/ed25519"
	"net/http"

	"github.com/system-transparency/stfe/types"
)

func (lp *LogParameters) parseAddEntryV1Request(r *http.Request) (*types.Leaf, error) {
	var req types.LeafRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}

	if pub, msg, sig := ed25519.PublicKey(req.VerificationKey[:]), req.Message.Marshal(), req.Signature[:]; !ed25519.Verify(pub, msg, sig) {
		return nil, fmt.Errorf("Invalid signature")
	}
	// TODO: check shard hint
	// TODO: check domain hint
	return &types.Leaf{
		Message: req.Message,
		SigIdent: types.SigIdent{
			Signature: req.Signature,
			KeyHash:   types.Hash(req.VerificationKey[:]),
		},
	}, nil
}

func (lp *LogParameters) parseAddCosignatureRequest(r *http.Request) (*types.CosignatureRequest, error) {
	var req types.CosignatureRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("unpackOctetPost: %v", err)
	}
	if _, ok := lp.Witnesses[*req.KeyHash]; !ok {
		return nil, fmt.Errorf("Unknown witness: %x", req.KeyHash)
	}
	return &req, nil
}

func (lp *LogParameters) parseGetConsistencyProofRequest(r *http.Request) (*types.ConsistencyProofRequest, error) {
	var req types.ConsistencyProofRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}
	if req.OldSize < 1 {
		return nil, fmt.Errorf("OldSize(%d) must be larger than zero", req.OldSize)
	}
	if req.NewSize <= req.OldSize {
		return nil, fmt.Errorf("NewSize(%d) must be larger than OldSize(%d)", req.NewSize, req.OldSize)
	}
	return &req, nil
}

//func (lp *LogParameters) parseGetProofByHashV1Request(r *http.Request) (*types.GetProofByHashV1, error) {
//	var item types.GetProofByHashV1
//	if err := unpackOctetPost(r, &item); err != nil {
//		return nil, fmt.Errorf("unpackOctetPost: %v", err)
//	}
//	if item.TreeSize < 1 {
//		return nil, fmt.Errorf("TreeSize(%d) must be larger than zero", item.TreeSize)
//	}
//	return &item, nil
//}
//
//func (lp *LogParameters) parseGetEntriesV1Request(r *http.Request) (*types.GetEntriesV1, error) {
//	var item types.GetEntriesV1
//	if err := unpackOctetPost(r, &item); err != nil {
//		return nil, fmt.Errorf("unpackOctetPost: %v", err)
//	}
//
//	if item.Start > item.End {
//		return nil, fmt.Errorf("start(%v) must be less than or equal to end(%v)", item.Start, item.End)
//	}
//	if item.End-item.Start+1 > uint64(lp.MaxRange) {
//		item.End = item.Start + uint64(lp.MaxRange) - 1
//	}
//	return &item, nil
//}
//
//func unpackOctetPost(r *http.Request, out interface{}) error {
//	body, err := ioutil.ReadAll(r.Body)
//	if err != nil {
//		return fmt.Errorf("failed reading request body: %v", err)
//	}
//	if err := types.Unmarshal(body, out); err != nil {
//		return fmt.Errorf("Unmarshal: %v", err)
//	}
//	return nil
//}
