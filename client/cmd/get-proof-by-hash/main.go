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
	sthStr      = flag.String("sth", "", "base64-encoded StItem of type StFormatSignedTreeHeadV1 (default: fetch new sth)")
	leafHashStr = flag.String("leaf_hash", "", "base64-encoded leaf hash")
)

func main() {
	flag.Parse()
	defer glog.Flush()

	client, err := client.NewClientFromFlags()
	if err != nil {
		glog.Errorf("NewClientFromFlags: %v", err)
		return
	}
	leafHash, sth, err := newParamsFromFlags(client)
	if err != nil {
		glog.Errorf("NewRequestFromFlags: %v", err)
		return
	}

	proof, err := client.GetProofByHash(context.Background(), leafHash, sth)
	if err != nil {
		glog.Errorf("GetProofByHash: %v", err)
		return
	}
	serialized, err := types.Marshal(*proof)
	if err != nil {
		glog.Errorf("Marshal: %v", err)
	}
	fmt.Println("proof:", base64.StdEncoding.EncodeToString(serialized))
}

func newParamsFromFlags(client *client.Client) ([]byte, *types.StItem, error) {
	serialized, err := base64.StdEncoding.DecodeString(*sthStr)
	if err != nil {
		return nil, nil, fmt.Errorf("sth: DecodeString: %v", err)
	}
	var item types.StItem
	if err = types.Unmarshal(serialized, &item); err != nil {
		return nil, nil, fmt.Errorf("sth: Unmarshal: %v", err)
	} else if got, want := item.Format, types.StFormatSignedTreeHeadV1; got != want {
		return nil, nil, fmt.Errorf("unexpected StItem format: %v", got)
	}
	leafHash, err := base64.StdEncoding.DecodeString(*leafHashStr)
	if err != nil {
		return nil, nil, fmt.Errorf("leaf_hash: DecodeString: %v", err)
	} else if got, want := len(leafHash), 32; got != want {
		return nil, nil, fmt.Errorf("leaf_hash: unexpected size: %v", got)
	}
	glog.V(3).Infof("created request parameters TreeSize(%d) and LeafHash(%s)", item.SignedTreeHeadV1.TreeHead.TreeSize, *leafHashStr)
	return leafHash, &item, nil
}
