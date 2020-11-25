package x509util

import (
	"fmt"
	"testing"
)

func TestNewEd25519PrivateKey(t *testing.T) {
	for _, table := range []struct {
		description string
		pem         []byte
		wantErr     bool
	}{
		{
			description: "bad block: unwanted white space",
			pem: []byte(`
				-----BEGIN PRIVATE KEY-----
				MC4CAQAwBQYDK2VwBCIEIH65lXoCT4N9q4mPmDcsmAqIqG9CrqrB4KV2nqBC9JlZ
				-----END PRIVATE KEY-----
			`),
			wantErr: true,
		},
		{
			description: "invalid block type",
			pem: []byte(`-----BEGIN CERTIFICATE-----
MIIBbDCCAR4CFDfeuu6XURfn7AE4WShuwZBHEaLIMAUGAytlcDBsMQswCQYDVQQG
EwJOQTELMAkGA1UECAwCTkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTELMAkG
A1UECwwCTkExFjAUBgNVBAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0BCQEW
Ak5BMB4XDTIwMTEwMzE4MzI0MFoXDTMyMDEyMTE4MzI0MFowRTELMAkGA1UEBhMC
QVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp
dHMgUHR5IEx0ZDAqMAUGAytlcAMhAJvk390ZvwULplBri03Od4LLz+Sf/OUHu+20
wik+T9y5MAUGAytlcANBANekliXq4ttoClBJDZoktIQxyHHNcWyXFrj1HlOaT5bC
I3GIqqZ60Ua3jKytnEsKsD2rLMPItDwmG6wYSecy2ws=
-----END CERTIFICATE-----`),
			wantErr: true,
		},
		{
			description: "bad block: too many",
			pem: []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH65lXoCT4N9q4mPmDcsmAqIqG9CrqrB4KV2nqBC9JlZ
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH65lXoCT4N9q4mPmDcsmAqIqG9CrqrB4KV2nqBC9JlZ
-----END PRIVATE KEY-----`),
			wantErr: true,
		},
		{
			description: "bad block bytes: truncated key",
			pem: []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH6
-----END PRIVATE KEY-----`),
			wantErr: true,
		},
		{
			description: "bad block bytes: not an ed25519 private key",
			pem: []byte(`-----BEGIN PRIVATE KEY-----
MIHcAgEBBEIAtxq7RExTFraqJYhyedPFppJiV05tXb1gxmn+9DGNsfmZ5aD2ZwDo
PoIVDYudwj7gDL4MXzJj7LUh6WW0qALm4MugBwYFK4EEACOhgYkDgYYABAAcg0Y3
WTBxfVuw/OPdLf65N6hmBoCGgW8DOhfRXtZNzqkf3u1LnNpWrt/Xva7K6uthvLRr
A3djeuCmg8MlHdtFYQDa9QSsc0ZBhp6Lg7JSED8nopQIvKPocsUejqJVDqJ4ZK1E
+2qB5BQl9vGLUpZ5HKkWvKvo8jpNbstVyeOFtvLfGg==
-----END PRIVATE KEY-----`),
			wantErr: true,
		},
		{
			description: "ok ed25519 private key",
			pem: []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH65lXoCT4N9q4mPmDcsmAqIqG9CrqrB4KV2nqBC9JlZ
-----END PRIVATE KEY-----`),
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
			pem: []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH65lXoCT4N9q4mPmDcsmAqIqG9CrqrB4KV2nqBC9JlZ
-----END PRIVATE KEY-----`),
			wantErr: true,
		},
		{
			description: "bad block bytes: not a certificate",
			pem: []byte(`-----BEGIN CERTIFICATE-----
MC4CAQAwBQYDK2VwBCIEIH65lXoCT4N9q4mPmDcsmAqIqG9CrqrB4KV2nqBC9JlZ
-----END CERTIFICATE-----`),
			wantErr: true,
		},
		{
			description: "bad block bytes: truncated certificate",
			pem: []byte(`-----BEGIN CERTIFICATE-----
MIIBbDCCAR4CFDfeuu6XURfn7AE4WShuwZBHEaLIMAUGAytlcDBsMQswCQYDVQQG
-----END CERTIFICATE-----`),
			wantErr: true,
		},
		{
			description: "bad block bytes: truncated certificate in list",
			pem: []byte(`-----BEGIN CERTIFICATE-----
MIIBbDCCAR4CFDfeuu6XURfn7AE4WShuwZBHEaLIMAUGAytlcDBsMQswCQYDVQQG
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB7jCCAaCgAwIBAgICEAAwBQYDK2VwMGwxCzAJBgNVBAYTAk5BMQswCQYDVQQI
DAJOQTELMAkGA1UEBwwCTkExCzAJBgNVBAoMAk5BMQswCQYDVQQLDAJOQTEWMBQG
A1UEAwwNc3RmZSB0ZXN0ZGF0YTERMA8GCSqGSIb3DQEJARYCTkEwHhcNMjAxMTAz
MTgzMjE4WhcNMzIwMTIxMTgzMjE4WjBsMQswCQYDVQQGEwJOQTELMAkGA1UECAwC
TkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTELMAkGA1UECwwCTkExFjAUBgNV
BAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0BCQEWAk5BMCowBQYDK2VwAyEA
F1yPPpjHKDAKN73pBFGXzAvIjdkLLimydu2y1HLMOiKjZjBkMB0GA1UdDgQWBBQ6
P7JQ7yXtrTh7YkVU0I78P9A+nDAfBgNVHSMEGDAWgBQBvsxROtKU6zmr/SxcfTMD
sAQcMTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIChDAFBgMrZXAD
QQBm1GMV0ADPnXRWnelCW9tcyTh0p9hKefuSy/MNx7/XLHKnM5fX+yHqD84QOxES
Vc510vi4dM8I+e/vcoBsmMQP
-----END CERTIFICATE-----`),
			wantErr: true,
		},
		{
			description: "bad block: unwanted white spaces",
			pem: []byte(`
				-----BEGIN CERTIFICATE-----
				MIIBbDCCAR4CFDfeuu6XURfn7AE4WShuwZBHEaLIMAUGAytlcDBsMQswCQYDVQQG
				EwJOQTELMAkGA1UECAwCTkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTELMAkG
				A1UECwwCTkExFjAUBgNVBAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0BCQEW
				Ak5BMB4XDTIwMTEwMzE4MzI0MFoXDTMyMDEyMTE4MzI0MFowRTELMAkGA1UEBhMC
				QVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp
				dHMgUHR5IEx0ZDAqMAUGAytlcAMhAJvk390ZvwULplBri03Od4LLz+Sf/OUHu+20
				wik+T9y5MAUGAytlcANBANekliXq4ttoClBJDZoktIQxyHHNcWyXFrj1HlOaT5bC
				I3GIqqZ60Ua3jKytnEsKsD2rLMPItDwmG6wYSecy2ws=
				-----END CERTIFICATE-----
			`),
			wantErr: true,
		},
		{
			description: "ok certificate list: empty",
			pem:         []byte{},
			wantSerial:  nil,
		},
		{
			description: "ok certificate list: size 1",
			pem: []byte(`-----BEGIN CERTIFICATE-----
MIIBbDCCAR4CFDfeuu6XURfn7AE4WShuwZBHEaLIMAUGAytlcDBsMQswCQYDVQQG
EwJOQTELMAkGA1UECAwCTkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTELMAkG
A1UECwwCTkExFjAUBgNVBAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0BCQEW
Ak5BMB4XDTIwMTEwMzE4MzI0MFoXDTMyMDEyMTE4MzI0MFowRTELMAkGA1UEBhMC
QVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp
dHMgUHR5IEx0ZDAqMAUGAytlcAMhAJvk390ZvwULplBri03Od4LLz+Sf/OUHu+20
wik+T9y5MAUGAytlcANBANekliXq4ttoClBJDZoktIQxyHHNcWyXFrj1HlOaT5bC
I3GIqqZ60Ua3jKytnEsKsD2rLMPItDwmG6wYSecy2ws=
-----END CERTIFICATE-----`),
			wantSerial: []string{
				"318961541902906095038704399034602270237826065096",
			},
		},
		{
			description: "ok certificate list: size 2",
			pem: []byte(`-----BEGIN CERTIFICATE-----
MIIBbDCCAR4CFDfeuu6XURfn7AE4WShuwZBHEaLIMAUGAytlcDBsMQswCQYDVQQG
EwJOQTELMAkGA1UECAwCTkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTELMAkG
A1UECwwCTkExFjAUBgNVBAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0BCQEW
Ak5BMB4XDTIwMTEwMzE4MzI0MFoXDTMyMDEyMTE4MzI0MFowRTELMAkGA1UEBhMC
QVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp
dHMgUHR5IEx0ZDAqMAUGAytlcAMhAJvk390ZvwULplBri03Od4LLz+Sf/OUHu+20
wik+T9y5MAUGAytlcANBANekliXq4ttoClBJDZoktIQxyHHNcWyXFrj1HlOaT5bC
I3GIqqZ60Ua3jKytnEsKsD2rLMPItDwmG6wYSecy2ws=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB7jCCAaCgAwIBAgICEAAwBQYDK2VwMGwxCzAJBgNVBAYTAk5BMQswCQYDVQQI
DAJOQTELMAkGA1UEBwwCTkExCzAJBgNVBAoMAk5BMQswCQYDVQQLDAJOQTEWMBQG
A1UEAwwNc3RmZSB0ZXN0ZGF0YTERMA8GCSqGSIb3DQEJARYCTkEwHhcNMjAxMTAz
MTgzMjE4WhcNMzIwMTIxMTgzMjE4WjBsMQswCQYDVQQGEwJOQTELMAkGA1UECAwC
TkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTELMAkGA1UECwwCTkExFjAUBgNV
BAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0BCQEWAk5BMCowBQYDK2VwAyEA
F1yPPpjHKDAKN73pBFGXzAvIjdkLLimydu2y1HLMOiKjZjBkMB0GA1UdDgQWBBQ6
P7JQ7yXtrTh7YkVU0I78P9A+nDAfBgNVHSMEGDAWgBQBvsxROtKU6zmr/SxcfTMD
sAQcMTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIChDAFBgMrZXAD
QQBm1GMV0ADPnXRWnelCW9tcyTh0p9hKefuSy/MNx7/XLHKnM5fX+yHqD84QOxES
Vc510vi4dM8I+e/vcoBsmMQP
-----END CERTIFICATE-----`),
			wantSerial: []string{
				"318961541902906095038704399034602270237826065096",
				"4096",
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
		}
		for i, certificate := range list {
			if got, want := fmt.Sprintf("%v", certificate.SerialNumber), table.wantSerial[i]; got != want {
				t.Errorf("Got serial number %s but wanted %s on index %d and test %q", got, want, i, table.description)
			}
		}
	}
}

func TestNewCertPool(t *testing.T) {
}

func TestParseDerChain(t *testing.T) {
}

func TestParseDerList(t *testing.T) {
}

func TestVerifyChain(t *testing.T) {
}
