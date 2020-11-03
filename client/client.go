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
	"github.com/system-transparency/stfe"
	"github.com/system-transparency/stfe/server/descriptor"
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

// AddEntry creates, signs, and adds a new ChecksumV1 entry to the log
func (c *Client) AddEntry(ctx context.Context, name, checksum []byte) (*stfe.StItem, error) {
	leaf, err := stfe.NewChecksumV1(name, checksum).Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed marshaling StItem: %v", err)
	}
	data, err := json.Marshal(stfe.AddEntryRequest{
		Item:            base64.StdEncoding.EncodeToString(leaf),
		Signature:       base64.StdEncoding.EncodeToString(ed25519.Sign(*c.PrivateKey, leaf)),
		SignatureScheme: uint16(tls.Ed25519),
		Chain:           c.b64Chain(),
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
	glog.V(2).Infof("created request: %s %s", req.Method, req.URL)

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

	if item.Format != stfe.StFormatSignedDebugInfoV1 {
		return nil, fmt.Errorf("bad StItem format: %v", item.Format)
	}
	if err := item.SignedDebugInfoV1.Verify(c.Log.Scheme, c.Log.PublicKey, leaf); err != nil {
		return nil, fmt.Errorf("bad SignedDebugInfoV1 signature: %v", err)
	}
	glog.V(2).Infof("add-entry request succeeded")
	return &item, nil
}

func (c *Client) GetSth(ctx context.Context) (*stfe.StItem, error) {
	glog.V(2).Info("creating get-sth request")
	return nil, fmt.Errorf("TODO")
}

func (c *Client) GetConsistencyProof(ctx context.Context, first, second uint64) (*stfe.StItem, error) {
	glog.V(2).Info("creating get-consistency-proof request")
	return nil, fmt.Errorf("TODO")
}

func (c *Client) GetProofByHash(ctx context.Context, treeSize uint64, hash []byte) (*stfe.StItem, error) {
	glog.V(2).Info("creating get-proof-by-hash request")
	return nil, fmt.Errorf("TODO")
}

func (c *Client) GetEntries(ctx context.Context, start, end uint64) (*stfe.StItem, error) {
	glog.V(2).Info("creating get-entries request")
	return nil, fmt.Errorf("TODO")
}

func (c *Client) GetAnchors(ctx context.Context, start, end uint64) ([]*x509.Certificate, error) {
	glog.V(2).Info("creating get-anchors request")
	return nil, fmt.Errorf("TODO")
}

func (c *Client) b64Chain() []string {
	chain := make([]string, 0, len(c.Chain))
	for _, cert := range c.Chain {
		chain = append(chain, base64.StdEncoding.EncodeToString(cert.Raw))
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

// protocol returns a protocol string that preceeds the log's base url
func (c *Client) protocol() string {
	if c.useHttp {
		return "http://"
	}
	return "https://"
}
