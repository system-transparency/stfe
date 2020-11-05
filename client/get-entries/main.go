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

	if client, err := client.NewClientFromPath(*logId, "", "", *operators, &http.Client{}, true); err != nil {
		glog.Fatal(err)
	} else if items, err := getRange(client, *start, *end); err != nil {
		glog.Fatal(err)
	} else if err := printRange(items); err != nil {
		glog.Fatal(err)
	}

	glog.Flush()
}

func getRange(client *client.Client, start, end uint64) ([]*stfe.StItem, error) {
	items := make([]*stfe.StItem, 0, end-start+1)
	for len(items) != cap(items) {
		rsps, err := client.GetEntries(context.Background(), start, end)
		if err != nil {
			return nil, fmt.Errorf("fetching entries failed: %v", err)
		}

		for _, rsp := range rsps {
			var item stfe.StItem
			if err := item.Unmarshal(rsp.Item); err != nil {
				return nil, fmt.Errorf("expected valid StItem but unmarshal failed: %v", err)
			} else if item.Format != stfe.StFormatChecksumV1 {
				return nil, fmt.Errorf("expected checksum_v1 but got: %v", item.Format)
			}
			items = append(items, &item)
		}
		start += uint64(len(rsps))
	}
	return items, nil
}

func printRange(items []*stfe.StItem) error {
	for i, item := range items {
		glog.V(3).Infof("Index(%d): %s", *start+uint64(i), item)
		str, err := item.MarshalB64()
		if err != nil {
			glog.Fatalf("expected valid StItem but marshal failed: %v", err)
		}
		fmt.Printf("Index(%d): %s\n", *start+uint64(i), str)
	}
	return nil
}
