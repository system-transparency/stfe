package descriptor

import (
	"bytes"
	"fmt"

	"encoding/base64"
	"encoding/json"
	"io/ioutil"

	"github.com/system-transparency/stfe/namespace"
)

// Operator is an stfe log operator that runs zero or more logs
type Operator struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Logs  []*Log `json:"logs"`
}

// Log is a collection of immutable stfe log parameters
type Log struct {
	Id      []byte `json:"id"`       // Serialized namespace
	BaseUrl string `json:"base_url"` // E.g., example.com/st/v1
	// TODO: List of supported namespace types?
}

func FindLog(ops []Operator, logId []byte) (*Log, error) {
	for _, op := range ops {
		for _, log := range op.Logs {
			if bytes.Equal(logId, log.Id) {
				return log, nil
			}
		}
	}
	return nil, fmt.Errorf("no such log: %s", base64.StdEncoding.EncodeToString(logId))
}

// LoadOperators loads a list of json-encoded log operators from a given path
func LoadOperators(path string) ([]Operator, error) {
	blob, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading log operators: %v", err)
	}
	var ops []Operator
	if err := json.Unmarshal(blob, &ops); err != nil {
		return nil, fmt.Errorf("failed decoding log operators: %v", err)
	}
	return ops, nil
}

func (l *Log) Namespace() (*namespace.Namespace, error) {
	var n namespace.Namespace
	if err := n.Unmarshal(l.Id); err != nil {
		return nil, fmt.Errorf("invalid namespace: %v", err)
	}
	return &n, nil
}
