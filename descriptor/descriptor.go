package descriptor

import (
	"bytes"
	"fmt"

	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
)

// Operator is an stfe log operator that runs zero or more logs
type Operator struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Logs  []*Log `json:"logs"`
}

// Log is a collection of immutable stfe log parameters
type Log struct {
	Id        []byte                `json:"id"`                // H(PublicKey)
	PublicKey []byte                `json:"public_key"`        // DER-encoded SubjectPublicKeyInfo
	Scheme    tls.SignatureScheme   `json:"signature_scheme"`  // Signature schemes used by the log (RFC 8446, §4.2.3)
	Schemes   []tls.SignatureScheme `json:"signature_schemes"` // Signature schemes that submitters can use (RFC 8446, §4.2.3)
	MaxChain  uint8                 `json:"max_chain"`         // maximum certificate chain length
	BaseUrl   string                `json:"base_url"`          // E.g., example.com/st/v1
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

// Key parses the log's public key
func (l *Log) Key() (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(l.PublicKey)
}
