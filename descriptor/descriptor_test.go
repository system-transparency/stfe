package descriptor

import (
	"fmt"
	"testing"

	"encoding/base64"
	"encoding/json"
)

const (
	operatorListJson = `[{"name":"Test operator","email":"test@example.com","logs":[{"id":"AAEgFKl1V+J3ib3Aav86UgGD7GRRtcKIdDhgc0G4vVD/TGc=","base_url":"example.com/st/v1"}]}]`
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
		ops       []Operator
		logId     []byte
		wantError bool
	}{
		{makeOperatorList(), deb64("AAEgFKl1V+J3ib3Aav86UgGD7GRRtcKIdDhgc0G4vVD/TGc="), false},
		{makeOperatorList(), []byte{0, 1, 2, 3}, true},
	} {
		_, err := FindLog(table.ops, table.logId)
		if (err != nil) != table.wantError {
			t.Errorf("wanted log not found for id: %v", table.logId)
		}
	}
}

func TestNamespace(t *testing.T) {
	for _, table := range []struct {
		description string
		id []byte
		wantErr bool
	}{
		{
			description: "invalid: not a namespace",
			id: []byte{0,1,2,3},
			wantErr: true,
		},
		{
			description: "valid",
			id: deb64("AAEgFKl1V+J3ib3Aav86UgGD7GRRtcKIdDhgc0G4vVD/TGc="),
		},
	}{
		l := &Log{ Id: table.id, BaseUrl: "example.com/st/v1" }
		_, err := l.Namespace()
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("wanted error %v but got %v in test %q: %v", got, want, table.description, err)
			return
		}
	}
}

func makeOperatorList() []Operator {
	return []Operator{
		Operator{
			Name:  "Test operator",
			Email: "test@example.com",
			Logs: []*Log{
				&Log{
					Id:        deb64("AAEgFKl1V+J3ib3Aav86UgGD7GRRtcKIdDhgc0G4vVD/TGc="),
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
