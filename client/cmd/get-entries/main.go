package main

import (
	"context"
	"flag"
	"fmt"

	"encoding/base64"

	"github.com/golang/glog"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/system-transparency/stfe/client"
	"github.com/system-transparency/stfe/types"
)

var (
	start = flag.Uint64("start", 0, "inclusive start index to download")
	end   = flag.Uint64("end", 0, "inclusive stop index to download")
)

func main() {
	flag.Parse()
	defer glog.Flush()

	client, err := client.NewClientFromFlags()
	if err != nil {
		glog.Errorf("NewClientFromFlags: %v", err)
		return
	}
	items, err := getRange(client, *start, *end)
	if err != nil {
		glog.Errorf("getRange: %v", err)
		return
	}
	if err := printRange(items); err != nil {
		glog.Errorf("printRange: %v", err)
		return
	}
}

func getRange(client *client.Client, start, end uint64) ([]*types.StItem, error) {
	items := make([]*types.StItem, 0, end-start+1)
	for len(items) != cap(items) {
		rsp, err := client.GetEntries(context.Background(), start, end)
		if err != nil {
			return nil, fmt.Errorf("fetching entries failed: %v", err)
		}
		items = append(items, rsp...)
		start += uint64(len(rsp))
	}
	return items, nil
}

func printRange(items []*types.StItem) error {
	for i, item := range items {
		var status string
		msg, err := types.Marshal(item.SignedChecksumV1.Data)
		if err != nil {
			return fmt.Errorf("Marshal data failed: %v", err)
		}
		sig := item.SignedChecksumV1.Signature.Signature
		namespace := &item.SignedChecksumV1.Signature.Namespace
		if err := namespace.Verify(msg, sig); err != nil {
			status = "unverified signature"
		} else {
			status = "verified signature"
		}
		serializedNamespace, err := types.Marshal(*namespace)
		if err != nil {
			return fmt.Errorf("Marshal namespace failed: %v", err)
		}
		serializedLeaf, err := types.Marshal(*item)
		if err != nil {
			return fmt.Errorf("Marshal item on index %d: %v", *start+uint64(i), err)
		}
		fmt.Printf("Index(%d) - %s\n", *start+uint64(i), status)
		fmt.Printf("-> Namespace: %s\n", base64.StdEncoding.EncodeToString(serializedNamespace))
		fmt.Printf("-> Identifier: %s\n", string(item.SignedChecksumV1.Data.Identifier))
		fmt.Printf("-> Checksum: %s\n", base64.StdEncoding.EncodeToString(item.SignedChecksumV1.Data.Checksum))
		fmt.Printf("-> Leaf hash: %s\n", base64.StdEncoding.EncodeToString(rfc6962.DefaultHasher.HashLeaf(serializedLeaf)))
	}
	return nil
}
