package types

import (
	"bytes"
	"strings"
	"testing"

	"encoding/binary"
)

// testCaseType is a common test case used for ST log types
type testCaseType struct {
	description string
	item        interface{}
	wantErr     bool
	wantBytes   []byte // only used if no error and not equal to nil
}

// TestMarshalUnmarshal tests that valid ST log structures can be marshalled and
// then unmarshalled without error, and that invalid ST log structures cannot be
// marshalled.  If wantBytes is non-nil the marshalled result must also match.
func TestMarshalUnmarshal(t *testing.T) {
	var tests []testCaseType
	tests = append(tests, test_cases_stitemlist(t)...)
	tests = append(tests, test_cases_stitem(t)...)
	tests = append(tests, test_cases_sthv1(t)...)
	tests = append(tests, test_cases_costhv1(t)...)
	tests = append(tests, test_cases_cpv1(t)...)
	tests = append(tests, test_cases_ipv1(t)...)
	tests = append(tests, test_cases_signed_checksumv1(t)...)
	tests = append(tests, test_cases_checksumv1(t)...)
	tests = append(tests, test_cases_thv1(t)...)
	tests = append(tests, test_cases_nh(t)...)
	tests = append(tests, test_cases_sigv1(t)...)
	tests = append(tests, test_cases_namespace(t)...)
	tests = append(tests, test_cases_ed25519v1(t)...)
	for _, table := range tests {
		b, err := Marshal(table.item)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue // nothing to unmarshal
		}
		if got, want := b, table.wantBytes; want != nil && !bytes.Equal(got, want) {
			t.Errorf("got bytes \n%v\n\tbut wanted\n%v\n\t in test %q: %v", got, want, table.description, err)
		}

		switch table.item.(type) {
		case StItemList:
			var item StItemList
			err = Unmarshal(b, &item)
		case StItem:
			var item StItem
			err = Unmarshal(b, &item)
		case SignedTreeHeadV1:
			var item SignedTreeHeadV1
			err = Unmarshal(b, &item)
		case CosignedTreeHeadV1:
			var item CosignedTreeHeadV1
			err = Unmarshal(b, &item)
		case ConsistencyProofV1:
			var item ConsistencyProofV1
			err = Unmarshal(b, &item)
		case InclusionProofV1:
			var item InclusionProofV1
			err = Unmarshal(b, &item)
		case SignedChecksumV1:
			var item SignedChecksumV1
			err = Unmarshal(b, &item)
		case ChecksumV1:
			var item ChecksumV1
			err = Unmarshal(b, &item)
		case TreeHeadV1:
			var item TreeHeadV1
			err = Unmarshal(b, &item)
		case NodeHash:
			var item NodeHash
			err = Unmarshal(b, &item)
		case SignatureV1:
			var item SignatureV1
			err = Unmarshal(b, &item)
		case Namespace:
			var item Namespace
			err = Unmarshal(b, &item)
		case Ed25519V1:
			var item Ed25519V1
			err = Unmarshal(b, &item)
		default:
			t.Errorf("unhandled type in test %q", table.description)
		}
		if err != nil {
			t.Errorf("unmarshal failed but wanted success in test %q: %v", table.description, err)
		}
	}
}

// TestUnmarshalStItem tests that invalid StItems cannot be unmarshalled
func TestUnmarshalStItem(t *testing.T) {
	tests := test_cases_stitem(t)[1:] // skip reserved type
	for _, table := range tests {
		description := table.description[7:] // skip "valid: " prefix
		b, err := Marshal(table.item)
		if err != nil {
			t.Fatalf("must marshal in test %q: %v", description, err)
		}

		var item StItem
		if err := Unmarshal(append(b[:], []byte{0}...), &item); err == nil {
			t.Errorf("unmarshal suceeded with one extra byte in test %q", description)
		}
		if err := Unmarshal(b[:len(b)-1], &item); err == nil {
			t.Errorf("unmarshal suceeded with one byte short in test %q", description)
		}
		if err := Unmarshal(append(b[:], b[:]...), &item); err == nil {
			t.Errorf("unmarshal succeeded with appended StItem in test %q", description)
		}
		if err := Unmarshal([]byte{0}, &item); err == nil {
			t.Errorf("unmarshal succeeded with a single byte in test %q", description)
		}
	}
}

// TestStItemString checks that the String() function prints the right format,
// and that following body is printed in a verbose mode without a nil-ptr panic.
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
	tests := append(test_cases_stitem(t), testCaseType{
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

var (
	// StItemList
	testStItemList = StItemList{
		Items: []StItem{
			testStItemSignedChecksumV1,
			testStItemInclusionProofV1,
			testStItemCosignedTreeHeadV1,
		},
	}
	testStItemListBytes = bytes.Join([][]byte{
		func() []byte {
			sum := uint32(len(testStItemSignedChecksumV1Bytes))
			sum += uint32(len(testStItemInclusionProofV1Bytes))
			sum += uint32(len(testStItemCosignedTreeHeadV1Bytes))
			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, sum)
			return buf
		}(), // length specifier list
		testStItemSignedChecksumV1Bytes,   // first StItem
		testStItemInclusionProofV1Bytes,   // second StItem
		testStItemCosignedTreeHeadV1Bytes, // third StItem
	}, nil)

	// StItem
	testStItemReserved = StItem{
		Format: StFormatReserved,
	}

	testStItemSignedTreeHeadV1 = StItem{
		Format:           StFormatSignedTreeHeadV1,
		SignedTreeHeadV1: &testSignedTreeHeadV1,
	}
	testStItemSignedTreeHeadV1Bytes = bytes.Join([][]byte{
		[]byte{0x00, 0x01},        // format signed_tree_head_v1
		testSignedTreeHeadV1Bytes, // SignedTreeHeadV1
	}, nil)

	testStItemCosignedTreeHeadV1 = StItem{
		Format:             StFormatCosignedTreeHeadV1,
		CosignedTreeHeadV1: &testCosignedTreeHeadV1,
	}
	testStItemCosignedTreeHeadV1Bytes = bytes.Join([][]byte{
		[]byte{0x00, 0x02},          // format cosigned_tree_head_v1
		testCosignedTreeHeadV1Bytes, // CosignedTreeHeadV1,
	}, nil)

	testStItemConsistencyProofV1 = StItem{
		Format:             StFormatConsistencyProofV1,
		ConsistencyProofV1: &testConsistencyProofV1,
	}
	testStItemConsistencyProofV1Bytes = bytes.Join([][]byte{
		[]byte{0x00, 0x03},          // format consistency_proof_v1
		testConsistencyProofV1Bytes, // ConsistencyProofV1
	}, nil)

	testStItemInclusionProofV1 = StItem{
		Format:           StFormatInclusionProofV1,
		InclusionProofV1: &testInclusionProofV1,
	}
	testStItemInclusionProofV1Bytes = bytes.Join([][]byte{
		[]byte{0x00, 0x04},        // format inclusion_proof_v1
		testInclusionProofV1Bytes, // InclusionProofV1
	}, nil)

	testStItemSignedChecksumV1 = StItem{
		Format:           StFormatSignedChecksumV1,
		SignedChecksumV1: &testSignedChecksumV1,
	}
	testStItemSignedChecksumV1Bytes = bytes.Join([][]byte{
		[]byte{0x00, 0x05},        // format signed_checksum_v1
		testSignedChecksumV1Bytes, // SignedChecksumV1
	}, nil)

	// Subtypes used by StItem
	testSignedTreeHeadV1 = SignedTreeHeadV1{
		TreeHead:  testTreeHeadV1,
		Signature: testSignatureV1,
	}
	testSignedTreeHeadV1Bytes = bytes.Join([][]byte{
		testTreeHeadV1Bytes,  // tree head
		testSignatureV1Bytes, // signature
	}, nil)

	testCosignedTreeHeadV1 = CosignedTreeHeadV1{
		SignedTreeHead: testSignedTreeHeadV1,
		Cosignatures: []SignatureV1{
			testSignatureV1,
		},
	}
	testCosignedTreeHeadV1Bytes = bytes.Join([][]byte{
		testSignedTreeHeadV1Bytes,                                 // signed tree head
		[]byte{0x00, 0x00, 0x00, byte(len(testSignatureV1Bytes))}, // cosignature length specifier
		testSignatureV1Bytes,                                      // the only cosignature in this list
	}, nil)

	testConsistencyProofV1 = ConsistencyProofV1{
		LogId:     testNamespace,
		TreeSize1: 16909060,
		TreeSize2: 16909060,
		ConsistencyPath: []NodeHash{
			testNodeHash,
		},
	}
	testConsistencyProofV1Bytes = bytes.Join([][]byte{
		testNamespaceBytes, // log id
		[]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}, // tree size 1
		[]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}, // tree size 2
		[]byte{0x00, byte(len(testNodeHashBytes))},             // consistency path length specifier
		testNodeHashBytes, // the only node hash in this proof
	}, nil)

	testInclusionProofV1 = InclusionProofV1{
		LogId:     testNamespace,
		TreeSize:  16909060,
		LeafIndex: 16909060,
		InclusionPath: []NodeHash{
			testNodeHash,
		},
	}
	testInclusionProofV1Bytes = bytes.Join([][]byte{
		testNamespaceBytes, // log id
		[]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}, // tree size
		[]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}, // leaf index
		[]byte{0x00, byte(len(testNodeHashBytes))},             // inclusion path length specifier
		testNodeHashBytes, // the only node hash in this proof
	}, nil)

	testSignedChecksumV1 = SignedChecksumV1{
		Data:      testChecksumV1,
		Signature: testSignatureV1,
	}
	testSignedChecksumV1Bytes = bytes.Join([][]byte{
		testChecksumV1Bytes,  // data
		testSignatureV1Bytes, // signature
	}, nil)

	// Additional subtypes
	testChecksumV1 = ChecksumV1{
		Identifier: []byte("foobar-1-2-3"),
		Checksum:   make([]byte, 32),
	}
	testChecksumV1Bytes = bytes.Join([][]byte{
		[]byte{12},             // identifier length specifier
		[]byte("foobar-1-2-3"), // identifier
		[]byte{32},             // checksum length specifier
		make([]byte, 32),       // checksum
	}, nil)

	testTreeHeadV1 = TreeHeadV1{
		Timestamp: 16909060,
		TreeSize:  16909060,
		RootHash:  testNodeHash,
		Extension: make([]byte, 0),
	}
	testTreeHeadV1Bytes = bytes.Join([][]byte{
		[]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}, // timestamp
		[]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}, // tree size
		testNodeHashBytes,  // root hash
		[]byte{0x00, 0x00}, // extension length specifier
		// no extension
	}, nil)

	testNodeHash = NodeHash{
		Data: make([]byte, 32),
	}
	testNodeHashBytes = bytes.Join([][]byte{
		[]byte{32}, // node hash length specifier
		make([]byte, 32),
	}, nil)

	testSignatureV1 = SignatureV1{
		Namespace: testNamespace,
		Signature: make([]byte, 64),
	}
	testSignatureV1Bytes = bytes.Join([][]byte{
		testNamespaceBytes, // namespace field
		[]byte{0, 64},      // signature length specifier
		make([]byte, 64),   // signature
	}, nil)
)

// test_cases_stitemlist returns test cases for the StItemList type
func test_cases_stitemlist(t *testing.T) []testCaseType {
	t.Helper()
	return []testCaseType{
		testCaseType{
			description: "test_cases_stitemlist: valid: StItemList: empty",
			item:        StItemList{},
			wantBytes:   []byte{0x00, 0x00, 0x00, 0x00},
		}, // skip max len check because it is huge
		testCaseType{
			description: "test_cases_stitemlist: valid: mixed content",
			item:        testStItemList,
			wantBytes:   testStItemListBytes,
		}, // other invalid bounds are already tested in subtypes
	}
}

// test_cases_stitem returns test cases for the different StItem types
func test_cases_stitem(t *testing.T) []testCaseType {
	t.Helper()
	return []testCaseType{
		{
			description: "invalid: StItem: reserved",
			item:        testStItemReserved,
			wantErr:     true,
		},
		{
			description: "valid: StItem: signed_tree_head_v1",
			item:        testStItemSignedTreeHeadV1,
			wantBytes:   testStItemSignedTreeHeadV1Bytes,
		},
		{
			description: "valid: StItem: cosigned_tree_head_v1",
			item:        testStItemCosignedTreeHeadV1,
			wantBytes:   testStItemCosignedTreeHeadV1Bytes,
		},
		{
			description: "valid: StItem: consistency_proof_v1",
			item:        testStItemConsistencyProofV1,
			wantBytes:   testStItemConsistencyProofV1Bytes,
		},
		{
			description: "valid: StItem: inclusion_proof_v1",
			item:        testStItemInclusionProofV1,
			wantBytes:   testStItemInclusionProofV1Bytes,
		},
		{
			description: "valid: StItem: signed_checksum_v1",
			item:        testStItemSignedChecksumV1,
			wantBytes:   testStItemSignedChecksumV1Bytes,
		}, // other invalid bounds are already tested in subtypes
	}
}

// test_cases_sthv1 returns test cases for the SignedTreeHeadV1 structure
func test_cases_sthv1(t *testing.T) []testCaseType {
	t.Helper()
	return []testCaseType{
		{
			description: "valid: testSignedTreeHeadV1",
			item:        testSignedTreeHeadV1,
			wantBytes:   testSignedTreeHeadV1Bytes,
		}, // other invalid bounds are already tested in subtypes
	}
}

// test_cases_costhv1 returns test cases for the CosignedTreeHeadV1 structure
func test_cases_costhv1(t *testing.T) []testCaseType {
	t.Helper()
	return []testCaseType{
		{
			description: "test_cases_costhv1: valid: min",
			item: CosignedTreeHeadV1{
				SignedTreeHead: testSignedTreeHeadV1,
				Cosignatures:   make([]SignatureV1, 0),
			},
		}, // skipping "valid: max" because it is huge
		{
			description: "test_cases_costhv1: testCosignedTreeHeadV1",
			item:        testCosignedTreeHeadV1,
			wantBytes:   testCosignedTreeHeadV1Bytes,
		}, // other invalid bounds are already tested in subtypes
	}
}

// test_cases_cpv1 returns test cases for the ConsistencyProofV1 structure
func test_cases_cpv1(t *testing.T) []testCaseType {
	t.Helper()
	max := 65535 // max consistency proof
	return []testCaseType{
		{
			description: "test_cases_cpv1: invalid: >max",
			item: ConsistencyProofV1{
				LogId:     testNamespace,
				TreeSize1: 0,
				TreeSize2: 0,
				ConsistencyPath: func() []NodeHash {
					var path []NodeHash
					for sum := 0; sum < max+1; sum += 1 + len(testNodeHash.Data) {
						path = append(path, testNodeHash)
					}
					return path
				}(),
			},
			wantErr: true,
		},
		{
			description: "test_cases_cpv1: valid: min",
			item: ConsistencyProofV1{
				LogId:           testNamespace,
				TreeSize1:       0,
				TreeSize2:       0,
				ConsistencyPath: make([]NodeHash, 0),
			},
		},
		{
			description: "test_cases_cpv1: valid: testConsistencyProofV1",
			item:        testConsistencyProofV1,
			wantBytes:   testConsistencyProofV1Bytes,
		}, // other invalid bounds are already tested in subtypes
	}
}

// test_cases_ipv1 returns test cases for the InclusionProofV1 structure
func test_cases_ipv1(t *testing.T) []testCaseType {
	t.Helper()
	max := 65535 // max inclusion proof
	return []testCaseType{
		{
			description: "test_cases_ipv1: invalid: >max",
			item: InclusionProofV1{
				LogId:     testNamespace,
				TreeSize:  0,
				LeafIndex: 0,
				InclusionPath: func() []NodeHash {
					var path []NodeHash
					for sum := 0; sum < max+1; sum += 1 + len(testNodeHash.Data) {
						path = append(path, testNodeHash)
					}
					return path
				}(),
			},
			wantErr: true,
		},
		{
			description: "test_cases_ipv1: valid: min",
			item: InclusionProofV1{
				LogId:         testNamespace,
				TreeSize:      0,
				LeafIndex:     0,
				InclusionPath: make([]NodeHash, 0),
			},
		},
		{
			description: "test_cases_ipv1: valid: testInclusionProofV1",
			item:        testInclusionProofV1,
			wantBytes:   testInclusionProofV1Bytes,
		}, // other invalid bounds are already tested in subtypes
	}
}

// test_cases_signed_checksumv1 returns test cases for the SignedChecksumV1 structure
func test_cases_signed_checksumv1(t *testing.T) []testCaseType {
	t.Helper()
	return []testCaseType{
		{
			description: "test_cases_signed_checksumv1: valid: testSignedChecksumV1",
			item:        testSignedChecksumV1,
			wantBytes:   testSignedChecksumV1Bytes,
		}, // other invalid bounds are already tested in subtypes
	}
}

// test_cases_checksumv1 returns test cases for the ChecksumV1 structure
func test_cases_checksumv1(t *testing.T) []testCaseType {
	t.Helper()
	minIdentifier, maxIdentifier, identifier := 1, 128, []byte("foobar-1-2-3")
	minChecksum, maxChecksum, checksum := 1, 64, make([]byte, 32)
	return []testCaseType{
		{
			description: "test_cases_checksumv1: invalid: identifier: min",
			item: ChecksumV1{
				Identifier: make([]byte, minIdentifier-1),
				Checksum:   checksum,
			},
			wantErr: true,
		},
		{
			description: "test_cases_checksumv1: invalid: identifier: max",
			item: ChecksumV1{
				Identifier: make([]byte, maxIdentifier+1),
				Checksum:   checksum,
			},
			wantErr: true,
		},
		{
			description: "test_cases_checksumv1: invalid: checksum: min",
			item: ChecksumV1{
				Identifier: identifier,
				Checksum:   make([]byte, minChecksum-1),
			},
			wantErr: true,
		},
		{
			description: "test_cases_checksumv1: invalid: checksum: max",
			item: ChecksumV1{
				Identifier: identifier,
				Checksum:   make([]byte, maxChecksum+1),
			},
			wantErr: true,
		},
		{
			description: "test_cases_checksumv1: valid: testChecksumV1",
			item:        testChecksumV1,
			wantBytes:   testChecksumV1Bytes,
		},
	}
}

// test_cases_thv1 returns test cases for the TreeHeadV1 structure
func test_cases_thv1(t *testing.T) []testCaseType {
	t.Helper()
	min, max := 0, 1<<16-1 // extensions min and max
	return []testCaseType{
		{
			description: "test_cases_thv1: invalid: max",
			item: TreeHeadV1{
				Timestamp: 0,
				TreeSize:  0,
				RootHash:  testNodeHash,
				Extension: make([]byte, max+1),
			},
			wantErr: true,
		},
		{
			description: "test_cases_thv1: valid: min",
			item: TreeHeadV1{
				Timestamp: 0,
				TreeSize:  0,
				RootHash:  testNodeHash,
				Extension: make([]byte, min),
			},
		},
		{
			description: "test_cases_thv1: valid: max",
			item: TreeHeadV1{
				Timestamp: 0,
				TreeSize:  0,
				RootHash:  testNodeHash,
				Extension: make([]byte, max),
			},
		},
		{
			description: "test_cases_thv1: valid: testTreeHeadV1",
			item:        testTreeHeadV1,
			wantBytes:   testTreeHeadV1Bytes,
		}, // other invalid bounds are already tested in subtypes
	}
}

// test_cases_nh returns test cases for the NodeHash structure
func test_cases_nh(t *testing.T) []testCaseType {
	t.Helper()
	min, max := 32, 1<<8-1 // NodeHash min and max
	return []testCaseType{
		{
			description: "test_cases_nh: invalid: min",
			item:        NodeHash{make([]byte, min-1)},
			wantErr:     true,
		},
		{
			description: "test_cases_nh: invalid: max",
			item:        NodeHash{make([]byte, max+1)},
			wantErr:     true,
		},
		{
			description: "test_cases_nh: valid: min",
			item:        NodeHash{make([]byte, min)},
		},
		{
			description: "test_cases_nh: valid: max",
			item:        NodeHash{make([]byte, max)},
		},
		{
			description: "test_cases_nh: valid: testNodeHash",
			item:        testNodeHash,
			wantBytes:   testNodeHashBytes,
		}, // other invalid bounds are already tested in subtypes
	}
}

// test_cases_sigv1 returns test cases for the SignatureV1 structure
func test_cases_sigv1(t *testing.T) []testCaseType {
	t.Helper()
	min, max := 1, 1<<16-1 // signature min and max
	return []testCaseType{
		{
			description: "test_cases_sigv1: invalid: min",
			item: SignatureV1{
				Namespace: testNamespace,
				Signature: make([]byte, min-1),
			},
			wantErr: true,
		},
		{
			description: "test_cases_sigv1: invalid: max",
			item: SignatureV1{
				Namespace: testNamespace,
				Signature: make([]byte, max+1),
			},
			wantErr: true,
		},
		{
			description: "test_cases_sigv1: valid: min",
			item: SignatureV1{
				Namespace: testNamespace,
				Signature: make([]byte, min),
			},
		},
		{
			description: "test_cases_sigv1: valid: max",
			item: SignatureV1{
				Namespace: testNamespace,
				Signature: make([]byte, max),
			},
		},
		{
			description: "test_cases_sigV1: valid: testSignatureV1",
			item:        testSignatureV1,
			wantBytes:   testSignatureV1Bytes,
		},
	}
}
