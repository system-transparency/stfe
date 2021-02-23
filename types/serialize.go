package types

import (
	"fmt"

	"github.com/google/certificate-transparency-go/tls"
)

// Marshal marshals a TLS-encodable structure
func Marshal(item interface{}) ([]byte, error) {
	serialized, err := tls.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("tls.Marshal: %v", err)
	}
	return serialized, nil
}

// Unmarshal unmarshals a TLS-encoded structure
func Unmarshal(serialized []byte, out interface{}) error {
	extra, err := tls.Unmarshal(serialized, out)
	if err != nil {
		return fmt.Errorf("tls.Unmarshal: %v", err)
	}
	if len(extra) > 0 {
		return fmt.Errorf("tls.Unmarshal: extra data: %X", extra)
	}
	return nil
}
