package stfe

import (
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/monitoring/prometheus"
)

var (
	reqcnt           monitoring.Counter   // number of incoming http requests
	rspcnt           monitoring.Counter   // number of valid http responses
	latency          monitoring.Histogram // request-response latency
	lastSthTimestamp monitoring.Gauge     // unix timestamp from the most recent sth
	lastSthSize      monitoring.Gauge     // tree size of most recent sth
)

func init() {
	mf := prometheus.MetricFactory{}
	reqcnt = mf.NewCounter("http_req", "number of http requests", "logid", "endpoint")
	rspcnt = mf.NewCounter("http_rsp", "number of http requests", "logid", "endpoint", "status")
	latency = mf.NewHistogram("http_latency", "http request-response latency", "logid", "endpoint", "status")
	lastSthTimestamp = mf.NewGauge("last_sth_timestamp", "unix timestamp while handling the most recent sth", "logid")
	lastSthSize = mf.NewGauge("last_sth_size", "most recent sth tree size", "logid")
}
