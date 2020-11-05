package stfe

import (
	"fmt"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"

	"github.com/system-transparency/stfe/x509util"
)

func (lp *LogParameters) buildChainFromDerList(derChain [][]byte) ([]*x509.Certificate, error) {
	certificate, intermediatePool, err := x509util.ParseDerChain(derChain)
	if err != nil {
		return nil, err
	}

	opts := x509.VerifyOptions{
		Roots:         lp.AnchorPool,
		Intermediates: intermediatePool,
		KeyUsages:     lp.KeyUsage, // no extended key usage passes by default
	}

	chains, err := certificate.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("chain verification failed: %v", err)
	}
	if len(chains) == 0 {
		return nil, fmt.Errorf("bad certificate chain length: empty")
	}

	// there might be several valid chains
	for _, chain := range chains {
		if int64(len(chain)) <= lp.MaxChain {
			return chain, nil // just pick the first valid chain
		}
	}
	return nil, fmt.Errorf("bad certificate chain length: too large")
}

// verifySignature checks if signature is valid for some serialized data.  The
// only supported signature scheme is ed25519(0x0807), see §4.2.3 in RFC 8446.
func (lp *LogParameters) verifySignature(certificate *x509.Certificate, scheme tls.SignatureScheme, serialized, signature []byte) error {
	if scheme != tls.Ed25519 {
		return fmt.Errorf("unsupported signature scheme: %v", scheme)
	}
	if err := certificate.CheckSignature(x509.PureEd25519, serialized, signature); err != nil {
		return fmt.Errorf("invalid signature: %v", err)
	}
	return nil
}

// genV1Sdi issues a new SignedDebugInfoV1 StItem from a serialized leaf value
func (lp *LogParameters) genV1Sdi(serialized []byte) (*StItem, error) {
	sig, err := lp.Signer.Sign(rand.Reader, serialized, crypto.Hash(0)) // ed25519
	if err != nil {
		return nil, fmt.Errorf("ed25519 signature failed: %v", err)
	}
	lastSdiTimestamp.Set(float64(time.Now().Unix()), lp.id())
	return NewSignedDebugInfoV1(lp.LogId, []byte("reserved"), sig), nil
}

// genV1Sth issues a new SignedTreeHeadV1 StItem from a TreeHeadV1 structure
func (lp *LogParameters) genV1Sth(th *TreeHeadV1) (*StItem, error) {
	serialized, err := th.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed tls marshaling tree head: %v", err)
	}
	sig, err := lp.Signer.Sign(rand.Reader, serialized, crypto.Hash(0)) // ed25519
	if err != nil {
		return nil, fmt.Errorf("ed25519 signature failed: %v", err)
	}
	lastSthTimestamp.Set(float64(time.Now().Unix()), lp.id())
	lastSthSize.Set(float64(th.TreeSize), lp.id())
	return NewSignedTreeHeadV1(th, lp.LogId, sig), nil
}
