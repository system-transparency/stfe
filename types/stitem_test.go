package types

import (
	"strings"
	"testing"
)

// TestStItemString checks that the String() function prints the right format,
// and that the body is printed without a nil-pointer panic.
func TestStItemString(t *testing.T) {
	wantPrefix := map[StFormat]string{
		StFormatReserved:           "Format(reserved)",
		StFormatSignedTreeHeadV1:   "Format(signed_tree_head_v1): &{TreeHead",
		StFormatCosignedTreeHeadV1: "Format(cosigned_tree_head_v1): &{SignedTreeHead",
		StFormatConsistencyProofV1: "Format(consistency_proof_v1): &{LogId",
		StFormatInclusionProofV1:   "Format(inclusion_proof_v1): &{LogId",
		StFormatSignedChecksumV1:   "Format(signed_checksum_v1): &{Data",
		StFormat(1<<16 - 1):        "unknown StItem: unknown StFormat: 65535",
	}
	tests := append(test_cases_stitem(t), testCaseSerialize{
		description: "valid: unknown StItem",
		item: StItem{
			Format: StFormat(1<<16 - 1),
		},
	})
	for _, table := range tests {
		item, ok := table.item.(StItem)
		if !ok {
			t.Fatalf("must cast to StItem in test %q", table.description)
		}

		prefix, ok := wantPrefix[item.Format]
		if !ok {
			t.Fatalf("must have prefix for StFormat %v in test %q", item.Format, table.description)
		}
		if got, want := item.String(), prefix; !strings.HasPrefix(got, want) {
			t.Errorf("got %q but wanted prefix %q in test %q", got, want, table.description)
		}
	}
}
