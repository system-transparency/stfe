package descriptor

import (
	"fmt"
	"testing"

	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
)

const (
	operatorListJson = `[{"name":"Test operator","email":"test@example.com","logs":[{"id":"B9oCJk4XIOMXba8dBM5yUj+NLtqTE6xHwbvR9dYkHPM=","public_key":"MCowBQYDK2VwAyEAqM4b/SHOCRId9xgiCPn8D8r6+Nrk9JTZZqW6vj7TGa0=","signature_scheme":2055,"signature_schemes":[2055],"max_chain":3,"base_url":"example.com/st/v1"}]}]`
)

func TestMarshal(t *testing.T) {
	for _, table := range []struct {
		in   []Operator
		want string
	}{
		{makeOperatorList(), operatorListJson},
	} {
		b, err := json.Marshal(table.in)
		if err != nil {
			t.Errorf("operator list marshaling failed: %v", err)
		}
		if string(b) != table.want {
			t.Errorf("\nwant %s\n got %s", table.want, string(b))
		}
	}

}

func TestUnmarshal(t *testing.T) {
	for _, table := range []struct {
		in   []byte
		want error
	}{
		{[]byte(operatorListJson), nil},
	} {
		var op []Operator
		if err := json.Unmarshal(table.in, &op); err != table.want {
			t.Errorf("wanted err=%v, got %v", table.want, err)
		}
	}
}

func TestFindLog(t *testing.T) {
	for _, table := range []struct {
		op        Operator
		logId     []byte
		wantError bool
	}{
		{makeOperatorList()[0], deb64("B9oCJk4XIOMXba8dBM5yUj+NLtqTE6xHwbvR9dYkHPM="), false},
		{makeOperatorList()[0], []byte{0, 1, 2, 3}, true},
	} {
		_, err := table.op.FindLog(table.logId)
		if (err != nil) != table.wantError {
			t.Errorf("wanted log not found for id: %v", table.logId)
		}
	}
}

func makeOperatorList() []Operator {
	pub := deb64("MCowBQYDK2VwAyEAqM4b/SHOCRId9xgiCPn8D8r6+Nrk9JTZZqW6vj7TGa0=")
	h := sha256.New()
	h.Write(pub)
	id := h.Sum(nil)
	return []Operator{
		Operator{
			Name:  "Test operator",
			Email: "test@example.com",
			Logs: []*Log{
				&Log{
					Id:        id,
					PublicKey: pub,
					Scheme:    tls.Ed25519,
					Schemes: []tls.SignatureScheme{
						tls.Ed25519,
					},
					MaxChain: 3,
					BaseUrl:  "example.com/st/v1",
				},
			},
		},
	}
}

func deb64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("failed decoding base64: %v", err))
	}
	return b
}
