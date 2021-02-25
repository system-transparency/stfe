package stfe

import (
	"fmt"

	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"github.com/system-transparency/stfe/types"
)

func NewTreeHeadV1FromLogRoot(lr *ttypes.LogRootV1) *types.TreeHeadV1 {
	return &types.TreeHeadV1{
		Timestamp: uint64(lr.TimestampNanos / 1000 / 1000),
		TreeSize:  uint64(lr.TreeSize),
		RootHash: types.NodeHash{
			Data: lr.RootHash,
		},
		Extension: make([]byte, 0),
	}
}

func NewNodePathFromHashPath(hashes [][]byte) []types.NodeHash {
	path := make([]types.NodeHash, 0, len(hashes))
	for _, hash := range hashes {
		path = append(path, types.NodeHash{hash})
	}
	return path
}

func NewStItemListFromLeaves(leaves []*trillian.LogLeaf) (*types.StItemList, error) {
	items := make([]types.StItem, 0, len(leaves))
	for _, leaf := range leaves {
		var item types.StItem
		if err := types.Unmarshal(leaf.LeafValue, &item); err != nil {
			return nil, fmt.Errorf("Unmarshal failed: %v", err)
		}
		items = append(items, item)
	}
	return &types.StItemList{items}, nil
}
