package stfe

import (
	"fmt"

	"crypto/sha256"

	"github.com/google/certificate-transparency-go/tls"
)

func ExampleNewChecksumV1() {
	name := "foobar-1.2.3"
	hasher := sha256.New()
	hasher.Write([]byte(name))
	checksum := hasher.Sum(nil) // hash of package name

	item, err := NewChecksumV1(name, checksum)
	if err != nil {
		fmt.Printf("failed creating checksum item: %v", err)
		return
	}
	fmt.Printf("%s\n", item)
	// Output: checksum_v1 foobar-1.2.3 UOeWe84malBvj2FLtQlr66WA0gUEa5GPR9I7LsYm114=
}

func ExampleMarshalChecksumV1() {
	item, err := NewChecksumV1("foobar-1.2.3", make([]byte, 32))
	if err != nil {
		fmt.Printf("failed creating checksum item: %v", err)
		return
	}

	b, err := tls.Marshal(item)
	if err != nil {
		fmt.Printf("tls.Marshal() failed: %v", err)
		return
	}
	fmt.Printf("%v\n", b)
	// Output: [0 5 12 102 111 111 98 97 114 45 49 46 50 46 51 32 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
}

func ExampleUnmarshalChecksumV1() {
	b := []byte{0, 5, 12, 102, 111, 111, 98, 97, 114, 45, 49, 46, 50, 46, 51, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	var item StItem
	extra, err := tls.Unmarshal(b, &item)
	if err != nil {
		fmt.Printf("tls.Unmarshal() failed: %v (%v)", err, extra)
		return
	} else if len(extra) > 0 {
		fmt.Printf("tls.Unmarshal() found extra data: %v", extra)
		return
	}
	fmt.Printf("%v\n", item)
	// Output: checksum_v1 foobar-1.2.3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
}
