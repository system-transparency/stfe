package stfe

import (
	"fmt"

	"crypto/sha256"
)

func ExampleNewChecksumV1() {
	name := []byte("foobar-1.2.3")
	hasher := sha256.New()
	hasher.Write([]byte(name))
	checksum := hasher.Sum(nil) // hash of package name

	item := NewChecksumV1(name, checksum)
	fmt.Printf("%s\n", item)
	// Output: Format(checksum_v1): Package(foobar-1.2.3) Checksum(UOeWe84malBvj2FLtQlr66WA0gUEa5GPR9I7LsYm114=)
}

func ExampleMarshalChecksumV1() {
	item := NewChecksumV1([]byte("foobar-1.2.3"), make([]byte, 32))
	b, err := item.Marshal()
	if err != nil {
		fmt.Printf("%v", err)
		return
	}
	fmt.Printf("%v\n", b)
	// Output: [0 5 12 102 111 111 98 97 114 45 49 46 50 46 51 32 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
}

func ExampleUnmarshalChecksumV1() {
	b := []byte{0, 5, 12, 102, 111, 111, 98, 97, 114, 45, 49, 46, 50, 46, 51, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	var item StItem
	if err := item.Unmarshal(b); err != nil {
		fmt.Printf("%v", err)
		return
	}
	fmt.Printf("%v\n", item)
	// Output: Format(checksum_v1): Package(foobar-1.2.3) Checksum(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=)
}
