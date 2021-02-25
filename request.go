package stfe

import (
	"fmt"

	"io/ioutil"
	"net/http"

	"github.com/system-transparency/stfe/types"
)

func (lp *LogParameters) parseAddEntryV1Request(r *http.Request) (*types.StItem, error) {
	var item types.StItem
	if err := unpackOctetPost(r, &item); err != nil {
		return nil, fmt.Errorf("unpackOctetPost: %v", err)
	}
	if item.Format != types.StFormatSignedChecksumV1 {
		return nil, fmt.Errorf("invalid StItem format: %v", item.Format)
	}

	// Check that submitter namespace is valid
	if namespace, ok := lp.Submitters.Find(&item.SignedChecksumV1.Signature.Namespace); !ok {
		return nil, fmt.Errorf("unknown namespace: %v", item.SignedChecksumV1.Signature.Namespace)
	} else if msg, err := types.Marshal(item.SignedChecksumV1.Data); err != nil {
		return nil, fmt.Errorf("Marshal: %v", err) // should never happen
	} else if err := namespace.Verify(msg, item.SignedChecksumV1.Signature.Signature); err != nil {
		return nil, fmt.Errorf("Verify: %v", err)
	}
	return &item, nil
}

func (lp *LogParameters) parseAddCosignatureV1Request(r *http.Request) (*types.StItem, error) {
	var item types.StItem
	if err := unpackOctetPost(r, &item); err != nil {
		return nil, fmt.Errorf("unpackOctetPost: %v", err)
	}
	if item.Format != types.StFormatCosignedTreeHeadV1 {
		return nil, fmt.Errorf("invalid StItem format: %v", item.Format)
	}

	// Check that witness namespace is valid
	if got, want := len(item.CosignedTreeHeadV1.Cosignatures), 1; got != want {
		return nil, fmt.Errorf("invalid number of cosignatures: %d", got)
	} else if namespace, ok := lp.Witnesses.Find(&item.CosignedTreeHeadV1.Cosignatures[0].Namespace); !ok {
		return nil, fmt.Errorf("unknown witness: %v", item.CosignedTreeHeadV1.Cosignatures[0].Namespace)
	} else if msg, err := types.Marshal(*types.NewSignedTreeHeadV1(&item.CosignedTreeHeadV1.SignedTreeHead.TreeHead, &item.CosignedTreeHeadV1.SignedTreeHead.Signature).SignedTreeHeadV1); err != nil {
		return nil, fmt.Errorf("Marshal: %v", err) // should never happen
	} else if err := namespace.Verify(msg, item.CosignedTreeHeadV1.Cosignatures[0].Signature); err != nil {
		return nil, fmt.Errorf("Verify: %v", err)
	}
	return &item, nil
}

func (lp *LogParameters) parseGetConsistencyProofV1Request(r *http.Request) (*types.GetConsistencyProofV1, error) {
	var item types.GetConsistencyProofV1
	if err := unpackOctetPost(r, &item); err != nil {
		return nil, fmt.Errorf("unpackOctetPost: %v", err)
	}
	if item.First < 1 {
		return nil, fmt.Errorf("first(%d) must be larger than zero", item.First)
	}
	if item.Second <= item.First {
		return nil, fmt.Errorf("second(%d) must be larger than first(%d)", item.Second, item.First)
	}
	return &item, nil
}

func (lp *LogParameters) parseGetProofByHashV1Request(r *http.Request) (*types.GetProofByHashV1, error) {
	var item types.GetProofByHashV1
	if err := unpackOctetPost(r, &item); err != nil {
		return nil, fmt.Errorf("unpackOctetPost: %v", err)
	}
	if item.TreeSize < 1 {
		return nil, fmt.Errorf("TreeSize(%d) must be larger than zero", item.TreeSize)
	}
	return &item, nil
}

func (lp *LogParameters) parseGetEntriesV1Request(r *http.Request) (*types.GetEntriesV1, error) {
	var item types.GetEntriesV1
	if err := unpackOctetPost(r, &item); err != nil {
		return nil, fmt.Errorf("unpackOctetPost: %v", err)
	}

	if item.Start > item.End {
		return nil, fmt.Errorf("start(%v) must be less than or equal to end(%v)", item.Start, item.End)
	}
	if item.End-item.Start+1 > uint64(lp.MaxRange) {
		item.End = item.Start + uint64(lp.MaxRange) - 1
	}
	return &item, nil
}

func unpackOctetPost(r *http.Request, out interface{}) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed reading request body: %v", err)
	}
	if err := types.Unmarshal(body, out); err != nil {
		return fmt.Errorf("Unmarshal: %v", err)
	}
	return nil
}
