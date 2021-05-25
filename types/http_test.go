package types

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

var (
	testZeroBuffer32 = [32]byte{}
	testZeroBuffer64 = [64]byte{}
)

func TestSignedTreeHeadToHTTP(t *testing.T) {
	description := "valid: cosigned tree head with two signatures"
	sth := &SignedTreeHead{
		TreeHead: TreeHead{
			Timestamp: 0,
			TreeSize:  0,
			RootHash:  testBuffer32,
		},
		SigIdent: []SigIdent{
			SigIdent{
				Signature: testZeroBuffer64,
				KeyHash:   testZeroBuffer32,
			},
			SigIdent{
				Signature: testBuffer64,
				KeyHash:   testBuffer32,
			},
		},
	}
	want := map[string][]string{
		HeaderTimestamp: []string{"0"},
		HeaderTreeSize:  []string{"0"},
		HeaderRootHash:  []string{hex.EncodeToString(testBuffer32[:])},
		HeaderSignature: []string{
			hex.EncodeToString(testZeroBuffer64[:]),
			hex.EncodeToString(testBuffer64[:]),
		},
		HeaderKeyHash: []string{
			hex.EncodeToString(testZeroBuffer32[:]),
			hex.EncodeToString(testBuffer32[:]),
		},
	}
	buf, err := sth.ToHTTP()
	if err != nil {
		t.Fatalf("sth.ToHTTP: %v", err)
	}
	hdr, err := headerFromBuf(buf)
	if err != nil {
		t.Fatalf("headerFromBuf: %v", err)
	}
	compareHeaderWithMap(t, description, hdr, want)
}

func TestConsistencyProofToHTTP(t *testing.T) { // TODO
}

func TestInclusionProofToHTTP(t *testing.T) { // TODO
}

func TestLeafToHTTP(t *testing.T) { // TODO
}

func TestSignedTreeHeadFromHTTP(t *testing.T) {
	for _, table := range []struct {
		description string
		buf         []byte
		wantErr     bool
		wantSth     *SignedTreeHead
	}{
		{
			description: "invalid: not ST log HTTP header",
			buf: newHeaderBuf(t, map[string][]string{
				"user-agent": []string{"secret"},
			}),
			wantErr: true,
		},
		{
			description: "invalid: timestamp",
			buf: newHeaderBuf(t, map[string][]string{
				HeaderTreeSize:  []string{"0"},
				HeaderRootHash:  []string{hex.EncodeToString(testBuffer32[:])},
				HeaderSignature: []string{hex.EncodeToString(testBuffer64[:])},
				HeaderKeyHash:   []string{hex.EncodeToString(testBuffer32[:])},
			}),
			wantErr: true,
		},
		{
			description: "invalid: tree size",
			buf: newHeaderBuf(t, map[string][]string{
				HeaderTimestamp: []string{"0"},
				HeaderRootHash:  []string{hex.EncodeToString(testBuffer32[:])},
				HeaderSignature: []string{hex.EncodeToString(testBuffer64[:])},
				HeaderKeyHash:   []string{hex.EncodeToString(testBuffer32[:])},
			}),
			wantErr: true,
		},
		{
			description: "invalid: root hash",
			buf: newHeaderBuf(t, map[string][]string{
				HeaderTimestamp: []string{"0"},
				HeaderTreeSize:  []string{"0"},
				HeaderSignature: []string{hex.EncodeToString(testBuffer64[:])},
				HeaderKeyHash:   []string{hex.EncodeToString(testBuffer32[:])},
			}),
			wantErr: true,
		},
		{
			description: "invalid: signature",
			buf: newHeaderBuf(t, map[string][]string{
				HeaderTimestamp: []string{"0"},
				HeaderTreeSize:  []string{"0"},
				HeaderRootHash:  []string{hex.EncodeToString(testBuffer32[:])},
				HeaderSignature: []string{hex.EncodeToString(testBuffer32[:])},
				HeaderKeyHash:   []string{hex.EncodeToString(testBuffer32[:])},
			}),
			wantErr: true,
		},
		{
			description: "invalid: key hash",
			buf: newHeaderBuf(t, map[string][]string{
				HeaderTimestamp: []string{"0"},
				HeaderTreeSize:  []string{"0"},
				HeaderRootHash:  []string{hex.EncodeToString(testBuffer32[:])},
				HeaderSignature: []string{hex.EncodeToString(testBuffer64[:])},
				HeaderKeyHash:   []string{hex.EncodeToString(testBuffer64[:])},
			}),
			wantErr: true,
		},
		{
			description: "invalid: sigident count",
			buf: newHeaderBuf(t, map[string][]string{
				HeaderTimestamp: []string{"0"},
				HeaderTreeSize:  []string{"0"},
				HeaderRootHash:  []string{hex.EncodeToString(testBuffer32[:])},
				HeaderSignature: []string{hex.EncodeToString(testBuffer64[:])},
				HeaderKeyHash: []string{
					hex.EncodeToString(testZeroBuffer32[:]),
					hex.EncodeToString(testBuffer32[:]),
				},
			}),
			wantErr: true,
		},
		{
			description: "invalid: no signer",
			buf: newHeaderBuf(t, map[string][]string{
				HeaderTimestamp: []string{"0"},
				HeaderTreeSize:  []string{"0"},
				HeaderRootHash:  []string{hex.EncodeToString(testBuffer32[:])},
			}),
			wantErr: true,
		},
		{
			description: "valid: cosigned tree head with two signatures",
			buf: newHeaderBuf(t, map[string][]string{
				HeaderTimestamp: []string{"0"},
				HeaderTreeSize:  []string{"0"},
				HeaderRootHash:  []string{hex.EncodeToString(testBuffer32[:])},
				HeaderSignature: []string{
					hex.EncodeToString(testZeroBuffer64[:]),
					hex.EncodeToString(testBuffer64[:]),
				},
				HeaderKeyHash: []string{
					hex.EncodeToString(testZeroBuffer32[:]),
					hex.EncodeToString(testBuffer32[:]),
				},
			}),
			wantSth: &SignedTreeHead{
				TreeHead: TreeHead{
					Timestamp: 0,
					TreeSize:  0,
					RootHash:  testBuffer32,
				},
				SigIdent: []SigIdent{
					SigIdent{
						Signature: testZeroBuffer64,
						KeyHash:   testZeroBuffer32,
					},
					SigIdent{
						Signature: testBuffer64,
						KeyHash:   testBuffer32,
					},
				},
			},
		},
	} {
		sth, err := SignedTreeHeadFromHTTP(table.buf)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue // nothing more to check on error
		}
		if got, want := sth, table.wantSth; !reflect.DeepEqual(got, want) {
			t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
	}
}

func TestHeaderFromBuf(t *testing.T) {
	for _, table := range []struct {
		description string
		buf         []byte
		wantErr     bool
		wantMap     map[string][]string
	}{
		{
			description: "invalid: split",
			buf:         []byte(HeaderPrefix + "k1: v1:v2\r\n"),
			wantErr:     true,
		},
		{
			description: "invalid: prefix",
			buf:         []byte("user-agent: secret\r\n"),
			wantErr:     true,
		},
		{
			description: "valid: one key with funky case",
			buf:         []byte(funkyCase(t, HeaderPrefix) + "k1: v1\r\n"),
			wantMap: map[string][]string{
				HeaderPrefix + "k1": []string{"v1"},
			},
		},
		{
			description: "valid: two keys where one has multiple values",
			buf: []byte(
				HeaderPrefix + "k1: v1 \r\n" +
					HeaderPrefix + "k2: v2\r\n" +
					HeaderPrefix + "k2: v3\r\n",
			),
			wantMap: map[string][]string{
				HeaderPrefix + "k1": []string{"v1"},
				HeaderPrefix + "k2": []string{"v2", "v3"},
			},
		},
	} {
		hdr, err := headerFromBuf(table.buf)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue // nothing more to check on error
		}
		compareHeaderWithMap(t, table.description, hdr, table.wantMap)
	}
}

func TestDecodeHex(t *testing.T) {
	for _, table := range []struct {
		description string
		hex         string
		wantErr     bool
		wantBuf     [4]byte
	}{
		{
			description: "invalid: too short input",
			hex:         "000102",
			wantErr:     true,
		},
		{
			description: "invalid: too large input",
			hex:         "0001020304",
			wantErr:     true,
		},
		{
			description: "invalid: not hex (1/2)",
			hex:         "000102030",
			wantErr:     true,
		},
		{
			description: "invalid: not hex (2/2)",
			hex:         "0001020q",
			wantErr:     true,
		},
		{
			description: "valid",
			hex:         "00010203",
			wantBuf:     [4]byte{0, 1, 2, 3},
		},
	} {
		var buf [4]byte
		err := decodeHex(table.hex, buf[:])
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue // nothing more to check on error
		}
		if got, want := buf[:], table.wantBuf[:]; !bytes.Equal(got, want) {
			t.Errorf("got buf %v but wanted %v in test %q", got, want, table.description)
		}
	}
}

func newHeaderBuf(t *testing.T, kv map[string][]string) []byte {
	t.Helper()
	hdr := http.Header{}
	for key, values := range kv {
		for _, value := range values {
			hdr.Add(key, value)
		}
	}
	buf := bytes.NewBuffer(nil)
	if err := hdr.Write(buf); err != nil {
		t.Fatalf("hdr.Write(): %v", err)
	}
	return buf.Bytes()
}

func compareHeaderWithMap(t *testing.T, description string, hdr http.Header, wantMap map[string][]string) {
	t.Helper()
	if got, want := len(hdr), len(wantMap); got != want {
		t.Errorf("got %d keys but wanted %d in test %q", got, want, description)
	}
	for key, value := range wantMap {
		if got, want := hdr.Values(key), value; !reflect.DeepEqual(got, want) {
			t.Errorf("got value %v but wanted %v for key %v in test %q", got, want, key, description)
		}
	}
}

func funkyCase(t *testing.T, str string) string {
	t.Helper()
	splitIndex := len(str) / 2
	return strings.ToLower(str[:splitIndex]) + strings.ToUpper(str[splitIndex:])
}
