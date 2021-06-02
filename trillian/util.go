package trillian

import (
	"fmt"

	trillian "github.com/google/trillian/types"
	siglog "github.com/system-transparency/stfe/types"
)

func treeHeadFromLogRoot(lr *trillian.LogRootV1) *siglog.TreeHead {
	var hash [siglog.HashSize]byte
	th := siglog.TreeHead{
		Timestamp: uint64(lr.TimestampNanos / 1000 / 1000 / 1000),
		TreeSize:  uint64(lr.TreeSize),
		RootHash:  &hash,
	}
	copy(th.RootHash[:], lr.RootHash)
	return &th
}

func nodePathFromHashes(hashes [][]byte) ([]*[siglog.HashSize]byte, error) {
	var path []*[siglog.HashSize]byte
	for _, hash := range hashes {
		if len(hash) != siglog.HashSize {
			return nil, fmt.Errorf("unexpected hash length: %v", len(hash))
		}

		var h [siglog.HashSize]byte
		copy(h[:], hash)
		path = append(path, &h)
	}
	return path, nil
}
