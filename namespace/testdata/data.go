package testdata

import (
	"encoding/base64"
)

var (
	Ed25519Vk = mustDecodeB64("HOQFUkKNWpjYAhNKTyWCzahlI7RDtf5123kHD2LACj0=")
	Ed25519Sk = mustDecodeB64("Zaajc50Xt1tNpTj6WYkljzcVjLXL2CcQcHFT/xZqYEcc5AVSQo1amNgCE0pPJYLNqGUjtEO1/nXbeQcPYsAKPQ==")
)

func mustDecodeB64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}
