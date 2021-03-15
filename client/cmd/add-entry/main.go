package main

import (
	"context"
	"flag"
	"fmt"

	"encoding/base64"

	"github.com/golang/glog"
	"github.com/system-transparency/stfe/client"
	"github.com/system-transparency/stfe/types"
)

var (
	identifier = flag.String("identifier", "foobar-1.2.3", "checksum identifier")
	checksum   = flag.String("checksum", "50e7967bce266a506f8f614bb5096beba580d205046b918f47d23b2ec626d75e", "base64-encoded checksum")
)

func main() {
	flag.Parse()
	defer glog.Flush()

	client, err := client.NewClientFromFlags()
	if err != nil {
		glog.Errorf("NewClientFromFlags: %v", err)
		return
	}
	data, err := NewChecksumV1FromFlags()
	if err != nil {
		glog.Errorf("NewChecksumV1FromFlags: %v", err)
		return
	}
	leafHash, err := client.AddEntry(context.Background(), data)
	if err != nil {
		glog.Errorf("AddEntry: %v", err)
		return
	}
	fmt.Println("leaf hash:", base64.StdEncoding.EncodeToString(leafHash))
}

func NewChecksumV1FromFlags() (*types.ChecksumV1, error) {
	var err error
	data := types.ChecksumV1{
		Identifier: []byte(*identifier),
	}
	data.Checksum, err = base64.StdEncoding.DecodeString(*checksum)
	if err != nil {
		return nil, fmt.Errorf("entry_checksum: DecodeString: %v", err)
	}
	return &data, nil
}
