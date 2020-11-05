package main

import (
	"context"
	"flag"
	"fmt"

	"net/http"

	"github.com/golang/glog"
	"github.com/system-transparency/stfe"
	"github.com/system-transparency/stfe/client"
)

var (
	operators = flag.String("operators", "../../descriptor/stfe.json", "path to json-encoded list of log operators")
	logId     = flag.String("log_id", "B9oCJk4XIOMXba8dBM5yUj+NLtqTE6xHwbvR9dYkHPM=", "base64-encoded log identifier")
	start     = flag.Uint64("start", 50, "inclusive start index to download")
	end       = flag.Uint64("end", 60, "inclusive stop index to download")
)

func main() {
	flag.Parse()

	client, err := client.NewClientFromPath(*logId, "", "", *operators, &http.Client{}, true)
	if err != nil {
		glog.Fatal(err)
	}

	items := make([]*stfe.StItem, 0, *end-*start+1)
	i := *start
	for len(items) != cap(items) {
		rsps, err := client.GetEntries(context.Background(), i, *end)
		if err != nil {
			glog.Fatal(err)
		}

		for _, rsp := range rsps {
			var item stfe.StItem
			if err := item.Unmarshal(rsp.Leaf); err != nil {
				glog.Fatalf("bad StItem: unmarshal failed: %v", err)
			} else if item.Format != stfe.StFormatChecksumV1 {
				glog.Fatalf("bad StFormat: %v", item.Format)
			}
			items = append(items, &item)
		}
		i += uint64(len(rsps))
	}

	for i, item := range items {
		glog.V(2).Infof("Index(%d): %s", *start+uint64(i), item)
		str, err := item.MarshalB64()
		if err != nil {
			glog.Fatalf("bad StItem: marshal failed: %v", err)
		}
		fmt.Printf("Index(%d): %s\n", *start+uint64(i), str)
	}

	glog.Flush()
}
