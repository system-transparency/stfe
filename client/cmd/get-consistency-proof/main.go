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
	first  = flag.String("first", "", "base64-encoded sth")
	second = flag.String("second", "", "base64-encoded sth")
)

func main() {
	flag.Parse()
	defer glog.Flush()

	client, err := client.NewClientFromFlags()
	if err != nil {
		glog.Errorf("NewClientFromFlags: %v", err)
		return
	}
	sth1, sth2, err := newParamsFromFlags()
	if err != nil {
		glog.Errorf("NewRequestFromFlags: %v", err)
		return
	}

	proof, err := client.GetConsistencyProof(context.Background(), sth1, sth2)
	if err != nil {
		glog.Errorf("GetConsistencyProof: %v", err)
		return
	}
	serialized, err := types.Marshal(*proof)
	if err != nil {
		glog.Errorf("Marshal: %v", err)
		return
	}
	fmt.Println("proof:", base64.StdEncoding.EncodeToString(serialized))
}

func newParamsFromFlags() (*types.StItem, *types.StItem, error) {
	sth1, err := decodeSthStr(*first)
	if err != nil {
		return nil, nil, fmt.Errorf("first: decodeSthStr: %v", err)
	}
	sth2, err := decodeSthStr(*second)
	if err != nil {
		return nil, nil, fmt.Errorf("second: decodeSthStr: %v", err)
	}
	return sth1, sth2, nil
}

func decodeSthStr(sthStr string) (*types.StItem, error) {
	serialized, err := base64.StdEncoding.DecodeString(sthStr)
	if err != nil {
		return nil, fmt.Errorf("DecodeString: %v", err)
	}
	var item types.StItem
	if err = types.Unmarshal(serialized, &item); err != nil {
		return nil, fmt.Errorf("Unmarshal: %v", err)
	}
	return &item, nil
}
