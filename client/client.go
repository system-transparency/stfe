package client

import (
	"bytes"
	"context"
	"crypto"
	"fmt"

	"io/ioutil"
	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/system-transparency/stfe"
	"github.com/system-transparency/stfe/types"
	"golang.org/x/net/context/ctxhttp"
)

// Descriptor is a log descriptor
type Descriptor struct {
	Namespace *types.Namespace // log identifier is a namespace
	Url       string           // log url, e.g., http://example.com/st/v1
}

// Client is a log client
type Client struct {
	HttpClient *http.Client
	Signer     crypto.Signer    // client's private identity
	Namespace  *types.Namespace // client's public identity
	Log        *Descriptor      // log's public identity
}

// GetLatestSth fetches and verifies the signature of the most recent STH.
// Outputs the resulting STH.
func (c *Client) GetLatestSth(ctx context.Context) (*types.StItem, error) {
	url := stfe.EndpointGetLatestSth.Path(c.Log.Url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating http request: %v", err)
	}
	glog.V(3).Infof("created http request: %s %s", req.Method, req.URL)

	item, err := c.doRequestWithStItemResponse(ctx, req)
	if err != nil {
		return nil, err
	}
	if got, want := item.Format, types.StFormatSignedTreeHeadV1; got != want {
		return nil, fmt.Errorf("unexpected StItem format: %v", got)
	}
	if err := VerifySignedTreeHeadV1(c.Log.Namespace, item); err != nil {
		return nil, fmt.Errorf("signature verification failed: %v", err)
	}
	glog.V(3).Infof("verified sth")
	return item, nil
}

// GetProofByHash fetches and verifies an inclusion proof for a leaf hash
// against an STH.  Outputs the resulting proof.
func (c *Client) GetProofByHash(ctx context.Context, leafHash []byte, sth *types.StItem) (*types.StItem, error) {
	if err := VerifySignedTreeHeadV1(c.Log.Namespace, sth); err != nil {
		return nil, fmt.Errorf("invalid sth: %v", err)
	}
	glog.V(3).Infof("verified sth")
	params := types.GetProofByHashV1{
		TreeSize: sth.SignedTreeHeadV1.TreeHead.TreeSize,
	}
	copy(params.Hash[:], leafHash)
	buf, err := types.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("req: Marshal: %v", err)
	}

	url := stfe.EndpointGetProofByHash.Path(c.Log.Url)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(buf))
	if err != nil {
		return nil, fmt.Errorf("failed creating http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	glog.V(3).Infof("created http request: %s %s", req.Method, req.URL)

	item, err := c.doRequestWithStItemResponse(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("doRequestWithStItemResponse: %v", err)
	}
	if got, want := item.Format, types.StFormatInclusionProofV1; got != want {
		return nil, fmt.Errorf("unexpected StItem format: %v", item.Format)
	}
	if err := VerifyInclusionProofV1(item, sth, params.Hash[:]); err != nil {
		return nil, fmt.Errorf("invalid inclusion proof: %v", err)
	}
	glog.V(3).Infof("verified inclusion proof")
	return item, nil
}

// GetConsistencyProof fetches and verifies a consistency proof betweeen two
// STHs.  Outputs the resulting proof.
func (c *Client) GetConsistencyProof(ctx context.Context, sth1, sth2 *types.StItem) (*types.StItem, error) {
	if err := VerifySignedTreeHeadV1(c.Log.Namespace, sth1); err != nil {
		return nil, fmt.Errorf("invalid first sth: %v", err)
	}
	if err := VerifySignedTreeHeadV1(c.Log.Namespace, sth2); err != nil {
		return nil, fmt.Errorf("invalid second sth: %v", err)
	}
	glog.V(3).Infof("verified sths")
	buf, err := types.Marshal(types.GetConsistencyProofV1{
		First:  sth1.SignedTreeHeadV1.TreeHead.TreeSize,
		Second: sth2.SignedTreeHeadV1.TreeHead.TreeSize,
	})
	if err != nil {
		return nil, fmt.Errorf("req: Marshal: %v", err)
	}

	url := stfe.EndpointGetConsistencyProof.Path(c.Log.Url)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(buf))
	if err != nil {
		return nil, fmt.Errorf("failed creating http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	glog.V(3).Infof("created http request: %s %s", req.Method, req.URL)

	item, err := c.doRequestWithStItemResponse(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("doRequestWithStItemResponse: %v", err)
	}
	if got, want := item.Format, types.StFormatConsistencyProofV1; got != want {
		return nil, fmt.Errorf("unexpected StItem format: %v", item.Format)
	}
	if err := VerifyConsistencyProofV1(item, sth1, sth2); err != nil {
		return nil, fmt.Errorf("invalid inclusion proof: %v", err)
	}
	glog.V(3).Infof("verified inclusion proof")
	return item, nil
}

// AddEntry signs and submits a checksum_v1 entry to the log.  Outputs the
// resulting leaf-hash on success.
func (c *Client) AddEntry(ctx context.Context, data *types.ChecksumV1) ([]byte, error) {
	msg, err := types.Marshal(*data)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling ChecksumV1: %v", err)
	}
	sig, err := c.Signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed signing ChecksumV1: %v", err)
	}
	leaf, err := types.Marshal(*types.NewSignedChecksumV1(data, &types.SignatureV1{
		Namespace: *c.Namespace,
		Signature: sig,
	}))
	if err != nil {
		return nil, fmt.Errorf("failed marshaling SignedChecksumV1: %v", err)
	}
	glog.V(3).Infof("signed checksum entry for identifier %q", string(data.Identifier))

	url := stfe.EndpointAddEntry.Path(c.Log.Url)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(leaf))
	if err != nil {
		return nil, fmt.Errorf("failed creating http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	glog.V(3).Infof("created http request: %s %s", req.Method, req.URL)

	if rsp, err := c.doRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("doRequest: %v", err)
	} else if len(rsp) != 0 {
		return nil, fmt.Errorf("extra data: %v", err)
	}
	glog.V(3).Infof("add-entry succeded")
	return rfc6962.DefaultHasher.HashLeaf(leaf), nil
}

// GetEntries fetches a range of entries from the log, verifying that they are
// of type signed_checksum_v1 but nothing more than that.  Outputs the resulting
// range that may be truncated by the log if [start,end] is too large.
func (c *Client) GetEntries(ctx context.Context, start, end uint64) ([]*types.StItem, error) {
	buf, err := types.Marshal(types.GetEntriesV1{
		Start: start,
		End:   end,
	})
	if err != nil {
		return nil, fmt.Errorf("Marshal: %v", err)
	}
	url := stfe.EndpointGetEntries.Path(c.Log.Url)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(buf))
	if err != nil {
		return nil, fmt.Errorf("failed creating http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	glog.V(3).Infof("created http request: %s %s", req.Method, req.URL)
	glog.V(3).Infof("request data: start(%d), end(%d)", start, end)

	body, err := c.doRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("doRequest: %v", err)
	}
	var list types.StItemList
	if err := types.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("Unmarshal: %v", err)
	}
	ret := make([]*types.StItem, 0, len(list.Items))
	for _, item := range list.Items {
		if got, want := item.Format, types.StFormatSignedChecksumV1; got != want {
			return nil, fmt.Errorf("unexpected StItem format: %v", got)
		}
		ret = append(ret, &item)
	}
	return ret, nil
}

// doRequest sends an HTTP request and outputs the raw body
func (c *Client) doRequest(ctx context.Context, req *http.Request) ([]byte, error) {
	rsp, err := ctxhttp.Do(ctx, c.HttpClient, req)
	if err != nil {
		return nil, fmt.Errorf("no response: %v", err)
	}
	defer rsp.Body.Close()
	if got, want := rsp.StatusCode, http.StatusOK; got != want {
		return nil, fmt.Errorf("bad http status: %v", got)
	}
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read body: %v", err)
	}
	return body, nil
}

//
// doRequestWithStItemResponse sends an HTTP request and returns a decoded
// StItem that the resulting HTTP response contained json:ed and marshaled
func (c *Client) doRequestWithStItemResponse(ctx context.Context, req *http.Request) (*types.StItem, error) {
	body, err := c.doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	var item types.StItem
	if err := types.Unmarshal(body, &item); err != nil {
		return nil, fmt.Errorf("failed decoding StItem: %v", err)
	}
	glog.V(9).Infof("got StItem: %v", item)
	return &item, nil
}
