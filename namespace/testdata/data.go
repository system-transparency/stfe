package testdata

import (
	"encoding/base64"
)

var (
	Ed25519Vk = mustDecodeB64("HOQFUkKNWpjYAhNKTyWCzahlI7RDtf5123kHD2LACj0=")
	Ed25519Sk = mustDecodeB64("Zaajc50Xt1tNpTj6WYkljzcVjLXL2CcQcHFT/xZqYEcc5AVSQo1amNgCE0pPJYLNqGUjtEO1/nXbeQcPYsAKPQ==")

	Ed25519Vk2 = mustDecodeB64("LqrWb9JwQUTk/SwTNDdMH8aRmy3mbmhwEepO5WSgb+A=")
	Ed25519Sk2 = mustDecodeB64("fDkSq4cWvG72yMhUyHVcZ72QKerZ66msgyVqDvfufZQuqtZv0nBBROT9LBM0N0wfxpGbLeZuaHAR6k7lZKBv4A==")

	Ed25519Vk3 = mustDecodeB64("Icd1U1oY0z+5iAwgCQZyGI+pycGs6GI2rQO8gAzT7Y0=")
	Ed25519Sk3 = mustDecodeB64("Q6uNL7VKv9flaBIXBXy/NyhNOicLYKKmfuJ6tLReMvQhx3VTWhjTP7mIDCAJBnIYj6nJwazoYjatA7yADNPtjQ==")
)

func mustDecodeB64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}
