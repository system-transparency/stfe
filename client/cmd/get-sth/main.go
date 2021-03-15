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

func main() {
	flag.Parse()
	defer glog.Flush()

	client, err := client.NewClientFromFlags()
	if err != nil {
		glog.Errorf("NewClientFromFlags: %v", err)
		return
	}
	sth, err := client.GetLatestSth(context.Background())
	if err != nil {
		glog.Errorf("GetLatestSth: %v", err)
		return
	}
	serialized, err := types.Marshal(*sth)
	if err != nil {
		glog.Errorf("Marshal: %v", err)
		return
	}
	fmt.Println("sth:", base64.StdEncoding.EncodeToString(serialized))
}
