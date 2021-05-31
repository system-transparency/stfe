package stfe

import (
	//"fmt"

	//"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"github.com/system-transparency/stfe/types"
)

func NewTreeHeadFromLogRoot(lr *ttypes.LogRootV1) *types.TreeHead {
	var hash [types.HashSize]byte
	th := types.TreeHead{
		Timestamp: uint64(lr.TimestampNanos / 1000 / 1000 / 1000),
		TreeSize:  uint64(lr.TreeSize),
		RootHash:  &hash,
	}
	copy(th.RootHash[:], lr.RootHash)
	return &th
}

func NodePathFromHashes(hashes [][]byte) []*[types.HashSize]byte {
	var path []*[types.HashSize]byte
	for _, hash := range hashes {
		var h [types.HashSize]byte
		copy(h[:], hash)
		path = append(path, &h)
	}
	return path
}

//func NewStItemListFromLeaves(leaves []*trillian.LogLeaf) (*types.StItemList, error) {
//	items := make([]types.StItem, 0, len(leaves))
//	for _, leaf := range leaves {
//		var item types.StItem
//		if err := types.Unmarshal(leaf.LeafValue, &item); err != nil {
//			return nil, fmt.Errorf("Unmarshal failed: %v", err)
//		}
//		items = append(items, item)
//	}
//	return &types.StItemList{items}, nil
//}
