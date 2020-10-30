package stfe

import (
	"fmt"

	"net/http"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
)

// checkGetLeavesByRange does santity-checking on a Trillian response
func checkGetLeavesByRange(rsp *trillian.GetLeavesByRangeResponse, req GetEntriesRequest) (int, error) {
	if len(rsp.Leaves) > int(req.End-req.Start+1) {
		return http.StatusInternalServerError, fmt.Errorf("backend GetLeavesByRange returned too many leaves: %d for [%d,%d]", len(rsp.Leaves), req.Start, req.End)
	}

	var lr types.LogRootV1
	if err := lr.UnmarshalBinary(rsp.GetSignedLogRoot().GetLogRoot()); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed unmarshaling log root: %v", err)
	}
	if uint64(req.Start) >= lr.TreeSize {
		return http.StatusBadRequest, fmt.Errorf("invalid start(%d): tree size is %d", req.Start, lr.TreeSize)
	}

	for i, leaf := range rsp.Leaves {
		if leaf.LeafIndex != req.Start+int64(i) {
			return http.StatusInternalServerError, fmt.Errorf("backend GetLeavesByRange returned unexpected leaf index: wanted %d, got %d", req.Start+int64(i), leaf.LeafIndex)
		}
	}
	return 0, nil
}
