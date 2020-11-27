package x509util

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/system-transparency/stfe/x509util/testdata"
)

func TestNewEd25519PrivateKey(t *testing.T) {
	for _, table := range []struct {
		description string
		pem         []byte
		wantErr     bool
	}{
		{
			description: "bad block: unwanted white space",
			pem:         testdata.Ed25519PrivateKeyBadWhiteSpace,
			wantErr:     true,
		},
		{
			description: "invalid block type",
			pem:         testdata.EndEntityCertificate,
			wantErr:     true,
		},
		{
			description: "bad block: trailing data",
			pem:         testdata.DoubleEd25519PrivateKey,
			wantErr:     true,
		},
		{
			description: "bad block bytes: truncated key",
			pem:         testdata.TruncatedEd25519PrivateKey,
			wantErr:     true,
		},
		{
			description: "bad block bytes: not an ed25519 private key",
			pem:         testdata.NotEd25519PrivateKey,
			wantErr:     true,
		},
		{
			description: "ok ed25519 private key",
			pem:         testdata.EndEntityPrivateKey,
		},
	} {
		_, err := NewEd25519PrivateKey(table.pem)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error=%v but wanted %v in test %q: %v", got, want, table.description, err)
		}
	}
}

func TestNewCertificateList(t *testing.T) {
	for _, table := range []struct {
		description string
		pem         []byte
		wantErr     bool
		wantSerial  []string
	}{
		{
			description: "invalid block type",
			pem:         testdata.EndEntityPrivateKey,
			wantErr:     true,
		},
		{
			description: "bad block bytes: not a certificate",
			pem:         testdata.NotACertificate,
			wantErr:     true,
		},
		{
			description: "bad block bytes: truncated certificate",
			pem:         testdata.TruncatedCertificate,
			wantErr:     true,
		},
		{
			description: "bad block bytes: truncated certificate in list",
			pem:         append(testdata.TruncatedCertificate, testdata.IntermediateCertificate...),
			wantErr:     true,
		},
		{
			description: "bad block: unwanted white spaces",
			pem:         testdata.CertificateBadWhiteSpace,
			wantErr:     true,
		},
		{
			description: "ok certificate list: empty",
			pem:         []byte{},
			wantSerial:  nil,
		},
		{
			description: "ok certificate list: size 1",
			pem:         testdata.EndEntityCertificate,
			wantSerial:  []string{testdata.EndEntityCertificateSerial},
		},
		{
			description: "ok certificate list: size 2",
			pem:         testdata.IntermediateChain,
			wantSerial:  []string{testdata.EndEntityCertificateSerial, testdata.IntermediateCertificateSerial},
		},
		{
			description: "ok certificate list: size 3",
			pem:         testdata.RootChain,
			wantSerial: []string{
				testdata.EndEntityCertificateSerial,
				testdata.IntermediateCertificateSerial,
				testdata.RootCertificateSerial,
			},
		},
	} {
		list, err := NewCertificateList(table.pem)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error=%v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := len(list), len(table.wantSerial); got != want {
			t.Errorf("got list of length %d but wanted %d in test %q", got, want, table.description)
			continue
		}
		for i, certificate := range list {
			if got, want := fmt.Sprintf("%v", certificate.SerialNumber), table.wantSerial[i]; got != want {
				t.Errorf("Got serial number %s but wanted %s on index %d and test %q", got, want, i, table.description)
			}
		}
	}
}

func TestNewCertPool(t *testing.T) {
	for i, pem := range [][]byte{
		testdata.EndEntityCertificate,
		testdata.IntermediateChain,
		testdata.RootChain,
	} {
		list, err := NewCertificateList(pem)
		if err != nil {
			t.Fatalf("must parse chain: %v", err)
		}
		pool := NewCertPool(list)
		if got, want := len(pool.Subjects()), len(list); got != want {
			t.Errorf("got pool of size %d but wanted %d in test %d", got, want, i)
			continue
		}
		for j, got := range pool.Subjects() {
			if want := list[j].RawSubject; !bytes.Equal(got, want) {
				t.Errorf("got subject[%d]=%X but wanted %X in test %d", j, got, want, i)
			}
		}
	}
}

// TODO: TestParseDerChain
func TestParseDerChain(t *testing.T) {
}

func TestParseDerList(t *testing.T) {
	for _, table := range []struct {
		description string
		list        [][]byte
		wantErr     bool
	}{
		{
			description: "invalid certificate: first byte is missing",
			list: [][]byte{
				mustMakeDerList(t, testdata.EndEntityCertificate)[0][1:],
			},
			wantErr: true,
		},
		{
			description: "valid certificate list: empty",
		},
		{
			description: "valid certificate list: size 1",
			list:        mustMakeDerList(t, testdata.EndEntityCertificate),
		},
		{
			description: "valid certificate list: size 2",
			list:        mustMakeDerList(t, testdata.IntermediateChain),
		},
		{
			description: "valid certificate list: size 3",
			list:        mustMakeDerList(t, testdata.RootChain),
		},
	} {
		list, err := ParseDerList(table.list)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error=%v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}

		if got, want := len(list), len(table.list); got != want {
			t.Errorf("got %d certifictes but wanted %d in test %q", got, want, table.description)
			continue
		}
		for i, cert := range list {
			if got, want := cert.Raw, table.list[i]; !bytes.Equal(got, want) {
				t.Errorf("got certificate bytes %X but wanted %X in test %q", got, want, table.description)
			}
		}
	}
}

// mustMakeDerList must create a list of DER-encoded certificates from PEM
func mustMakeDerList(t *testing.T, pem []byte) [][]byte {
	certs, err := NewCertificateList(pem)
	if err != nil {
		t.Fatalf("must parse pem-encoded certificates: %v", err)
	}

	list := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		list = append(list, cert.Raw)
	}
	return list
}

func TestVerifyChain(t *testing.T) {
	for _, table := range []struct {
		description string
		pem         []byte
		wantErr     bool
	}{
		{
			description: "invalid chain: intermediate did not sign end-entity",
			pem:         testdata.ChainBadIntermediate,
			wantErr:     true,
		},
		{
			description: "invalid chain: root did not sign intermediate",
			pem:         testdata.ChainBadRoot,
			wantErr:     true,
		},
		{
			description: "valid chain",
			pem:         testdata.RootChain,
		},
		{
			description: "valid chain 2",
			pem:         testdata.RootChain2,
		},
	} {
		chain, err := NewCertificateList(table.pem)
		if err != nil {
			t.Fatalf("must parse chain: %v", err)
		}
		err = VerifyChain(chain)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
	}
}
