package client

import (
	"bytes"
	"context"
	"fmt"

	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/system-transparency/stfe"
	"github.com/system-transparency/stfe/descriptor"
	"github.com/system-transparency/stfe/x509util"
	"golang.org/x/net/context/ctxhttp"
)

// Client is an HTTP(S) client that talks to an ST log
type Client struct {
	Log        *descriptor.Log
	Client     *http.Client
	Chain      []*x509.Certificate
	PrivateKey *ed25519.PrivateKey
	useHttp    bool
}

// NewClient returns a new log client
func NewClient(log *descriptor.Log, client *http.Client, useHttp bool, chain []*x509.Certificate, privateKey *ed25519.PrivateKey) *Client {
	return &Client{
		Log:        log,
		Chain:      chain,
		Client:     client,
		PrivateKey: privateKey,
		useHttp:    useHttp,
	}
}

// NewClientFromPath loads necessary data from file before creating a new
// client, namely, a pem-encoded certificate chain, a pem-encoded ed25519
// private key, and a json-encoded list of log operators (see descriptor).
// Chain and key paths may be left out by passing the empty string: "".
func NewClientFromPath(logId, chainPath, keyPath, operatorsPath string, cli *http.Client, useHttp bool) (*Client, error) {
	c, err := x509util.LoadChain(chainPath)
	if err != nil && chainPath != "" {
		return nil, err
	}

	k, err := x509util.LoadEd25519SigningKey(keyPath)
	if err != nil && keyPath != "" {
		return nil, err
	}

	ops, err := descriptor.LoadOperators(operatorsPath)
	if err != nil {
		return nil, err
	}

	id, err := base64.StdEncoding.DecodeString(logId)
	if err != nil {
		return nil, fmt.Errorf("failed decoding log identifier: %v", err)
	}

	log, err := descriptor.FindLog(ops, id)
	if err != nil {
		return nil, err
	}
	return NewClient(log, cli, useHttp, c, &k), nil
}

// AddEntry creates, signs, and adds a new ChecksumV1 entry to the log
func (c *Client) AddEntry(ctx context.Context, name, checksum []byte) (*stfe.StItem, error) {
	leaf, err := stfe.NewChecksumV1(name, checksum).Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed marshaling StItem: %v", err)
	}
	data, err := json.Marshal(stfe.AddEntryRequest{
		Item:            leaf,
		Signature:       ed25519.Sign(*c.PrivateKey, leaf),
		SignatureScheme: uint16(tls.Ed25519),
		Chain:           c.chain(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed creating post data: %v", err)
	}
	glog.V(3).Infof("created post data: %s", string(data))

	req, err := http.NewRequest("POST", c.protocol()+c.Log.BaseUrl+"/add-entry", bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed creating http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	glog.V(2).Infof("created http request: %s %s", req.Method, req.URL)

	item, err := c.doRequestWithStItemResponse(ctx, req)
	if err != nil {
		return nil, err
	}
	if item.Format != stfe.StFormatSignedDebugInfoV1 {
		return nil, fmt.Errorf("bad StItem format: %v", item.Format)
	}

	if k, err := c.Log.Key(); err != nil {
		return nil, fmt.Errorf("bad public key: %v", err)
	} else if err := VerifySignedDebugInfoV1(item, c.Log.Scheme, k, leaf); err != nil {
		return nil, fmt.Errorf("bad SignedDebugInfoV1 signature: %v", err)
	}
	return item, nil
}

// GetSth fetches and verifies the most recent STH.  Safe to use without a
// client chain and corresponding private key.
func (c *Client) GetSth(ctx context.Context) (*stfe.StItem, error) {
	req, err := http.NewRequest("GET", c.protocol()+c.Log.BaseUrl+"/get-sth", nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating http request: %v", err)
	}
	glog.V(2).Infof("created http request: %s %s", req.Method, req.URL)

	item, err := c.doRequestWithStItemResponse(ctx, req)
	if err != nil {
		return nil, err
	}
	if item.Format != stfe.StFormatSignedTreeHeadV1 {
		return nil, fmt.Errorf("bad StItem format: %v", item.Format)
	}

	if k, err := c.Log.Key(); err != nil {
		return nil, fmt.Errorf("bad public key: %v", err)
	} else if err := VerifySignedTreeHeadV1(item, c.Log.Scheme, k); err != nil {
		return nil, fmt.Errorf("bad SignedDebugInfoV1 signature: %v", err)
	}
	return item, nil
}

// GetConsistencyProof fetches and verifies a consistency proof between two
// STHs.  Safe to use without a client chain and corresponding private key.
func (c *Client) GetConsistencyProof(ctx context.Context, first, second *stfe.StItem) (*stfe.StItem, error) {
	req, err := http.NewRequest("GET", c.protocol()+c.Log.BaseUrl+"/get-consistency-proof", nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	q := req.URL.Query()
	q.Add("first", fmt.Sprintf("%d", first.SignedTreeHeadV1.TreeHead.TreeSize))
	q.Add("second", fmt.Sprintf("%d", second.SignedTreeHeadV1.TreeHead.TreeSize))
	req.URL.RawQuery = q.Encode()
	glog.V(2).Infof("created http request: %s %s", req.Method, req.URL)

	item, err := c.doRequestWithStItemResponse(ctx, req)
	if err != nil {
		return nil, err
	}
	if item.Format != stfe.StFormatConsistencyProofV1 {
		return nil, fmt.Errorf("bad StItem format: %v", item.Format)
	}
	if err := VerifyConsistencyProofV1(item, first, second); err != nil {
		return nil, fmt.Errorf("bad consistency proof: %v", err)
	}
	return item, nil
}

// GetProofByHash fetches and verifies an inclusion proof for a leaf against an
// STH.  Safe to use without a client chain and corresponding private key.
func (c *Client) GetProofByHash(ctx context.Context, treeSize uint64, rootHash, leaf []byte) (*stfe.StItem, error) {
	leafHash := rfc6962.DefaultHasher.HashLeaf(leaf)
	req, err := http.NewRequest("GET", c.protocol()+c.Log.BaseUrl+"/get-proof-by-hash", nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	q := req.URL.Query()
	q.Add("hash", base64.StdEncoding.EncodeToString(leafHash))
	q.Add("tree_size", fmt.Sprintf("%d", treeSize))
	req.URL.RawQuery = q.Encode()
	glog.V(2).Infof("created http request: %s %s", req.Method, req.URL)

	item, err := c.doRequestWithStItemResponse(ctx, req)
	if err != nil {
		return nil, err
	}
	if item.Format != stfe.StFormatInclusionProofV1 {
		return nil, fmt.Errorf("bad StItem format: %v", item.Format)
	}
	if err := VerifyInclusionProofV1(item, rootHash, leafHash); err != nil {
		return nil, fmt.Errorf("bad inclusion proof: %v", err)
	}
	return item, nil
}

func (c *Client) GetEntries(ctx context.Context, start, end uint64) ([]*stfe.GetEntryResponse, error) {
	req, err := http.NewRequest("GET", c.protocol()+c.Log.BaseUrl+"/get-entries", nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	q := req.URL.Query()
	q.Add("start", fmt.Sprintf("%d", start))
	q.Add("end", fmt.Sprintf("%d", end))
	req.URL.RawQuery = q.Encode()
	glog.V(2).Infof("created http request: %s %s", req.Method, req.URL)

	var rsp []*stfe.GetEntryResponse
	if err := c.doRequest(ctx, req, &rsp); err != nil {
		return nil, err
	}
	// TODO: verify signature over leaf data
	return rsp, nil
}

// GetAnchors fetches the log's trust anchors.  Safe to use without a client
// chain and corresponding private key.
func (c *Client) GetAnchors(ctx context.Context, start, end uint64) ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("TODO: Client.GetAnchors()")
}

func (c *Client) chain() [][]byte {
	chain := make([][]byte, 0, len(c.Chain))
	for _, cert := range c.Chain {
		chain = append(chain, cert.Raw)
	}
	return chain
}

// doRequest sends an HTTP request and decodes the resulting json body into out
func (c *Client) doRequest(ctx context.Context, req *http.Request, out interface{}) error {
	rsp, err := ctxhttp.Do(ctx, c.Client, req)
	if err != nil {
		return fmt.Errorf("http request failed: %v", err)
	}
	body, err := ioutil.ReadAll(rsp.Body)
	rsp.Body.Close()
	if err != nil {
		return fmt.Errorf("http body read failed: %v", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status code not ok: %v", rsp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("failed decoding json body: %v", err)
	}
	return nil
}

// doRequestWithStItemResponse sends an HTTP request and returns a decoded
// StItem that the resulting HTTP response contained json:ed and marshaled
func (c *Client) doRequestWithStItemResponse(ctx context.Context, req *http.Request) (*stfe.StItem, error) {
	var itemStr string
	if err := c.doRequest(ctx, req, &itemStr); err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(itemStr)
	if err != nil {
		return nil, fmt.Errorf("failed decoding base64 body: %v", err)
	}
	var item stfe.StItem
	if err := item.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("failed decoding StItem: %v", err)
	}
	glog.V(3).Infof("got StItem: %s", item)
	return &item, nil
}

// protocol returns a protocol string that preceeds the log's base url
func (c *Client) protocol() string {
	if c.useHttp {
		return "http://"
	}
	return "https://"
}
