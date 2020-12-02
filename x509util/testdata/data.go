package testdata

import (
	"bytes"
)

var (
	// EndEntityCertificate is a PEM-encoded end-entity certificate that is
	// signed by IntermediateCertificate
	EndEntityCertificate = []byte(`-----BEGIN CERTIFICATE-----
MIIBbDCCAR4CFDfeuu6XURfn7AE4WShuwZBHEaLIMAUGAytlcDBsMQswCQYDVQQG
EwJOQTELMAkGA1UECAwCTkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTELMAkG
A1UECwwCTkExFjAUBgNVBAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0BCQEW
Ak5BMB4XDTIwMTEwMzE4MzI0MFoXDTMyMDEyMTE4MzI0MFowRTELMAkGA1UEBhMC
QVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp
dHMgUHR5IEx0ZDAqMAUGAytlcAMhAJvk390ZvwULplBri03Od4LLz+Sf/OUHu+20
wik+T9y5MAUGAytlcANBANekliXq4ttoClBJDZoktIQxyHHNcWyXFrj1HlOaT5bC
I3GIqqZ60Ua3jKytnEsKsD2rLMPItDwmG6wYSecy2ws=
-----END CERTIFICATE-----`)
	// EndEntityCertificateSerial is the serial number of EndEntityCertificate
	EndEntityCertificateSerial = "318961541902906095038704399034602270237826065096"
	// EndEntityPrivateKey is the PEM-encoded Ed25519 private key of EndEntityCertificate
	EndEntityPrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDme3WaCwW2/FX095yh02yIIsn0D3vbvN5NsJzcdUwq1
-----END PRIVATE KEY-----`)

	// EndEntityCertificate2 is a PEM-encoded end-entity certificate that
	// is signed by IntermediateCertificate2
	EndEntityCertificate2 = []byte(`-----BEGIN CERTIFICATE-----
MIIBbDCCAR4CFC4G5ep2NoHAmvFkmFID7y4U/BryMAUGAytlcDBsMQswCQYDVQQG
EwJOQTELMAkGA1UECAwCTkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTELMAkG
A1UECwwCTkExFjAUBgNVBAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0BCQEW
Ak5BMB4XDTIwMTEyNTIxNTkwM1oXDTMyMDIxMjIxNTkwM1owRTELMAkGA1UEBhMC
QVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp
dHMgUHR5IEx0ZDAqMAUGAytlcAMhAKwG0O/Ql+L6O8aq8BZ+KOdJmVLdcnOmMENR
H7O84kVFMAUGAytlcANBAJIUg3wQ5AvhOaITYB/9rT5cm5dcklOdEIwAqvmSOEXf
vgCpSAz29bnKYJmjwp6mkXx3f31h39G41zr2wRjKnw8=
-----END CERTIFICATE-----`)
	// EndEntityCertificateSerial2 is the serial number of EndEntityCertificate2
	EndEntityCertificateSerial2 = "262767408425771953673235905171292083847897553650"
	// EndEntityPrivateKey2 is the PEM-encoded Ed25519 private key of EndEntityCertificate2
	EndEntityPrivateKey2 = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH65lXoCT4N9q4mPmDcsmAqIqG9CrqrB4KV2nqBC9JlZ
-----END PRIVATE KEY-----`)

	// IntermediateCertificate is a PEM-encoded intermediate certificate that is
	// signed by RootCertificate
	IntermediateCertificate = []byte(`-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`)
	// IntermediateCertificateSerial is the serial number of IntermediateCertificate
	IntermediateCertificateSerial = "4096"
	// IntermediatePrivateKey is the PEM-encoded Ed25519 private key of IntermediateCertificate
	IntermediatePrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEiZEO5PnjkbN4A+5r9LVTIZeVdPq/on5AzwnetZjszE
-----END PRIVATE KEY-----`)
	// IntermediateChain is a PEM-encoded certificate chain that is composed
	// of an end-entity certificate and an intermediate certificate
	IntermediateChain = bytes.Join([][]byte{
		EndEntityCertificate,
		IntermediateCertificate,
	}, []byte("\n"))

	// IntermediateCertificate2 is a PEM-encoded intermediate certificate that
	// is signed by RootCertificate2
	IntermediateCertificate2 = []byte(`-----BEGIN CERTIFICATE-----
MIIB7jCCAaCgAwIBAgICEAAwBQYDK2VwMGwxCzAJBgNVBAYTAk5BMQswCQYDVQQI
DAJOQTELMAkGA1UEBwwCTkExCzAJBgNVBAoMAk5BMQswCQYDVQQLDAJOQTEWMBQG
A1UEAwwNc3RmZSB0ZXN0ZGF0YTERMA8GCSqGSIb3DQEJARYCTkEwHhcNMjAxMTI1
MjE1NzU1WhcNMzIwMjEyMjE1NzU1WjBsMQswCQYDVQQGEwJOQTELMAkGA1UECAwC
TkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTELMAkGA1UECwwCTkExFjAUBgNV
BAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0BCQEWAk5BMCowBQYDK2VwAyEA
DD23ESkuIKaCkU6xCncIwvD12w4ETBgAiHAubr/wDwujZjBkMB0GA1UdDgQWBBSy
uua2yvX+VM9JBc19GQisnLnH5zAfBgNVHSMEGDAWgBQeeImH1qUrWk+pq3YOkwI8
bWdEuTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIChDAFBgMrZXAD
QQCoQvs8gPHZOH6VIuUGCcXVzf8D5+F6GZSoxMF880yYbdbUBVwwbJLFazwEn0uC
PwMBM9nZj3g1ZSH8uP2sEo0F
-----END CERTIFICATE-----`)
	// IntermediateCertificateSerial2 is the serial number of IntermediateCertificate2
	IntermediateCertificateSerial2 = "4096"
	// IntermediatePrivateKey2 is the PEM-encoded Ed25519 private key of IntermediateCertificate2
	IntermediatePrivateKey2 = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOo+qcT2GoWoAp0079ecz/ZyrCZ78Zqznv1xEoN96vT7
-----END PRIVATE KEY-----`)
	// IntermediateChain2 is a PEM-encoded certificate chain that is composed
	// of an end-entity certificate and an intermediate certificate
	IntermediateChain2 = bytes.Join([][]byte{
		EndEntityCertificate2,
		IntermediateCertificate2,
	}, []byte("\n"))

	// RootCertificate is a PEM-encoded root certificate
	RootCertificate = []byte(`-----BEGIN CERTIFICATE-----
MIIB/TCCAa+gAwIBAgIUDYJzaC5VSkKwiLVAxO5MyphAkN8wBQYDK2VwMGwxCzAJ
BgNVBAYTAk5BMQswCQYDVQQIDAJOQTELMAkGA1UEBwwCTkExCzAJBgNVBAoMAk5B
MQswCQYDVQQLDAJOQTEWMBQGA1UEAwwNc3RmZSB0ZXN0ZGF0YTERMA8GCSqGSIb3
DQEJARYCTkEwHhcNMjAxMTAzMTgzMTMxWhcNMzIwMTIxMTgzMTMxWjBsMQswCQYD
VQQGEwJOQTELMAkGA1UECAwCTkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTEL
MAkGA1UECwwCTkExFjAUBgNVBAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0B
CQEWAk5BMCowBQYDK2VwAyEAJ1IiXCB4YHwdWka9MM0bc7LvKAtksmtIo8IhkuEB
uzGjYzBhMB0GA1UdDgQWBBQBvsxROtKU6zmr/SxcfTMDsAQcMTAfBgNVHSMEGDAW
gBQBvsxROtKU6zmr/SxcfTMDsAQcMTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB
/wQEAwIChDAFBgMrZXADQQCXh6kDnE5giTjcLET2S94qTwnHVAj57DJcR/rf9Jy8
NMGbtzTL0/V0B8DHuJFA/islbZJbN7rSvqddEKL8N2gI
-----END CERTIFICATE-----`)
	// RootCertificateSerial is the serial number of RootCertificate
	RootCertificateSerial = "77126030260354546250480693976417574174523953375"
	// RootPrivateKey is the PEM-encoded Ed25519 private key of RootCertificate
	RootPrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPJGy4Tf9SwDv44lLCmVyEjsbUmwfTg+j/Xoyaunf1rx
-----END PRIVATE KEY-----`)
	// RootChain is a PEM-encoded certificate chain that contains an end-entity
	// certificate, an intermediate certificate, and a root certificate.
	RootChain = bytes.Join([][]byte{
		EndEntityCertificate,
		IntermediateCertificate,
		RootCertificate,
	}, []byte("\n"))

	// RootCertificate2 is a PEM-encoded root certificate
	RootCertificate2 = []byte(`-----BEGIN CERTIFICATE-----
MIIB/TCCAa+gAwIBAgIUCFGFq5zAkH03LQ2fpAamPhGd8FgwBQYDK2VwMGwxCzAJ
BgNVBAYTAk5BMQswCQYDVQQIDAJOQTELMAkGA1UEBwwCTkExCzAJBgNVBAoMAk5B
MQswCQYDVQQLDAJOQTEWMBQGA1UEAwwNc3RmZSB0ZXN0ZGF0YTERMA8GCSqGSIb3
DQEJARYCTkEwHhcNMjAxMTE3MTgxNTQyWhcNMzIwMjA0MTgxNTQyWjBsMQswCQYD
VQQGEwJOQTELMAkGA1UECAwCTkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTEL
MAkGA1UECwwCTkExFjAUBgNVBAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0B
CQEWAk5BMCowBQYDK2VwAyEAFOG1Lof1UiV2mYsM17EopyVCR87qRrNW9YHP0biu
pOyjYzBhMB0GA1UdDgQWBBQeeImH1qUrWk+pq3YOkwI8bWdEuTAfBgNVHSMEGDAW
gBQeeImH1qUrWk+pq3YOkwI8bWdEuTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB
/wQEAwIChDAFBgMrZXADQQDP4IQePN5Krr7jn+RM8AbF+c4fXgamA1XDHVIfXy/n
MexxZMsuSCSDq5XM5GMImffmBXA1dNJ6ytfJi668C+kF
-----END CERTIFICATE-----`)
	// RootCertificateSerial2 is the serial number of RootCertificate2
	RootCertificateSerial2 = "47489930858344783188475742157087612794308522072"
	// RootPrivateKey2 is the PEM-encoded Ed25519 private key of RootCertificate2
	RootPrivateKey2 = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKQd3B84w9pB6zJLGljuDyGKfz9uPP6QBeLiFcw0EME4
-----END PRIVATE KEY-----`)
	// RootChain2 is a PEM-encoded certificate chain that contains an end-entity
	// certificate, an intermediate certificate, and a root certificate.
	RootChain2 = bytes.Join([][]byte{
		EndEntityCertificate2,
		IntermediateCertificate2,
		RootCertificate2,
	}, []byte("\n"))
	
	// TrustAnchors is composed of two PEM-encoded trust anchors, namely,
	// RootCertificate and RootCertificate2.
	TrustAnchors = bytes.Join([][]byte{
		RootCertificate,
		RootCertificate2,
	}, []byte("\n"))
	// NumTrustAnchors is the number of test trust anchors
	NumTrustAnchors = 2

	// LogPrivateKey is an Ed25519 signing key
	LogPrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAhqlhKgY/TiEyTIe5BcZKLELGa2kODtJ3S+oMP4JwsA
-----END PRIVATE KEY-----`)

	// ExpiredCertificate is a PEM-encoded certificate that is always expired,
	// i.e., `Not Before`=`Not After`.  It is signed by IntermediateCertificate.
	ExpiredCertificate = []byte(`-----BEGIN CERTIFICATE-----
MIIBbDCCAR4CFFO1655aK8KvWIacn4KVPCo+3rgmMAUGAytlcDBsMQswCQYDVQQG
EwJOQTELMAkGA1UECAwCTkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTELMAkG
A1UECwwCTkExFjAUBgNVBAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0BCQEW
Ak5BMB4XDTIwMTIwMjE2MzI0MloXDTIwMTIwMjE2MzI0MlowRTELMAkGA1UEBhMC
QVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp
dHMgUHR5IEx0ZDAqMAUGAytlcAMhAFkRtny1XBNw3E7Bk8yE/dp1NfysaK9wevma
UQUqtJrHMAUGAytlcANBABXlP0XMtPhBwbilzJ6riD2j49uXFUkdYxP8jTCXyHw7
CrTlv9wj2MV3UJs7CQigEA21LJVENwYusMnGi2pTIQE=
-----END CERTIFICATE-----`)
	// ExpiredChain is an expired PEM-encoded certificate chain.  It is composed
	// of two certificates: ExpiredCertificate and IntermediateCertificate.
	ExpiredChain = bytes.Join([][]byte{
		ExpiredCertificate,
		IntermediateCertificate,
	}, []byte("\n"))

	// ChainBadIntermediate is a PEM-encoded certificate chain that contains
	// an end-entity certificate, an intermediate certificate, and a root
	// certificate.  However, the intermediate does not sign the end-entity.
	ChainBadIntermediate = bytes.Join([][]byte{
		EndEntityCertificate,
		IntermediateCertificate2,
		RootCertificate2,
	}, []byte("\n"))

	// ChainBadRoot is a PEM-encoded certificate chain that contains an
	// end-entity certificate, an intermediate certificate, and a root
	// certificate.  However, the root does not sign the intermediate.
	ChainBadRoot = bytes.Join([][]byte{
		EndEntityCertificate,
		IntermediateCertificate,
		RootCertificate2,
	}, []byte("\n"))

	// TruncatedCertificate is a truncated PEM-encoded certificate
	TruncatedCertificate = []byte(`-----BEGIN CERTIFICATE-----
MIIBbDCCAR4CFDfeuu6XURfn7AE4WShuwZBHEaLIMAUGAytlcDBsMQswCQYDVQQG
-----END CERTIFICATE-----`)

	// NotACertificate is a PEM-encoded certificate block that contains an
	// Ed25519 private key
	NotACertificate = []byte(`-----BEGIN CERTIFICATE-----
MC4CAQAwBQYDK2VwBCIEIH65lXoCT4N9q4mPmDcsmAqIqG9CrqrB4KV2nqBC9JlZ
-----END CERTIFICATE-----`)

	// NotEd25519PrivateKey is a PEM-encoded ECDSA private key
	NotEd25519PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIHcAgEBBEIAtxq7RExTFraqJYhyedPFppJiV05tXb1gxmn+9DGNsfmZ5aD2ZwDo
PoIVDYudwj7gDL4MXzJj7LUh6WW0qALm4MugBwYFK4EEACOhgYkDgYYABAAcg0Y3
WTBxfVuw/OPdLf65N6hmBoCGgW8DOhfRXtZNzqkf3u1LnNpWrt/Xva7K6uthvLRr
A3djeuCmg8MlHdtFYQDa9QSsc0ZBhp6Lg7JSED8nopQIvKPocsUejqJVDqJ4ZK1E
+2qB5BQl9vGLUpZ5HKkWvKvo8jpNbstVyeOFtvLfGg==
-----END PRIVATE KEY-----`)

	// TruncatedEd25519PrivateKey is a a PEM-encoded Ed25519 private key that
	// has a truncated block
	TruncatedEd25519PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH6
-----END PRIVATE KEY-----`)

	// DoubleEd25519PrivateKey is composed of two PEM-encoded Ed25519 private
	// keys
	DoubleEd25519PrivateKey = bytes.Join([][]byte{
		EndEntityPrivateKey,
		EndEntityPrivateKey2,
	}, []byte("\n"))

	// Ed25519PrivateKeyBadWhiteSpace is a PEM-encoded Ed25519 private key that
	// contains unwanted white space
	Ed25519PrivateKeyBadWhiteSpace = []byte(`
		-----BEGIN PRIVATE KEY-----
		MC4CAQAwBQYDK2VwBCIEIH65lXoCT4N9q4mPmDcsmAqIqG9CrqrB4KV2nqBC9JlZ
		-----END PRIVATE KEY-----`)

	// CertificateBadWhiteSpace is a PEM-encoded certificate that contains
	// unwanted white space
	CertificateBadWhiteSpace = []byte(`
		-----BEGIN CERTIFICATE-----
		MIIBbDCCAR4CFDfeuu6XURfn7AE4WShuwZBHEaLIMAUGAytlcDBsMQswCQYDVQQG
		EwJOQTELMAkGA1UECAwCTkExCzAJBgNVBAcMAk5BMQswCQYDVQQKDAJOQTELMAkG
		A1UECwwCTkExFjAUBgNVBAMMDXN0ZmUgdGVzdGRhdGExETAPBgkqhkiG9w0BCQEW
		Ak5BMB4XDTIwMTEwMzE4MzI0MFoXDTMyMDEyMTE4MzI0MFowRTELMAkGA1UEBhMC
		QVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp
		dHMgUHR5IEx0ZDAqMAUGAytlcAMhAJvk390ZvwULplBri03Od4LLz+Sf/OUHu+20
		wik+T9y5MAUGAytlcANBANekliXq4ttoClBJDZoktIQxyHHNcWyXFrj1HlOaT5bC
		I3GIqqZ60Ua3jKytnEsKsD2rLMPItDwmG6wYSecy2ws=
		-----END CERTIFICATE-----`)
)
