package client

import (
	"bytes"
	"context"
	"crypto"
	"flag"
	"fmt"
	"reflect"

	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io/ioutil"
	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/system-transparency/stfe"
	"github.com/system-transparency/stfe/types"
	"golang.org/x/net/context/ctxhttp"
)

var (
	logId      = flag.String("log_id", "AAEsY0retj4wa3S2fjsOCJCTVHab7ipEiMdqtW1uJ6Jvmg==", "base64-encoded log identifier")
	logUrl     = flag.String("log_url", "http://localhost:6965/st/v1", "log url")
	ed25519_sk = flag.String("ed25519_sk", "d8i6nud7PS1vdO0sIk9H+W0nyxbM63Y3/mSeUPRafWaFh8iH8QXvL7NaAYn2RZPrnEey+FdpmTYXE47OFO70eg==", "base64-encoded ed25519 signing key")
)

type Client struct {
	HttpClient *http.Client
	Signer     crypto.Signer    // client's private identity
	Namespace  *types.Namespace // client's public identity
	Log        *Descriptor      // log's public identity
}

type Descriptor struct {
	Namespace *types.Namespace // log identifier is a namespace
	Url       string           // log url, e.g., http://example.com/st/v1
}

func NewClientFromFlags() (*Client, error) {
	var err error
	c := Client{
		HttpClient: &http.Client{},
	}
	if len(*ed25519_sk) != 0 {
		sk, err := base64.StdEncoding.DecodeString(*ed25519_sk)
		if err != nil {
			return nil, fmt.Errorf("ed25519_sk: DecodeString: %v", err)
		}
		c.Signer = ed25519.PrivateKey(sk)
		c.Namespace, err = types.NewNamespaceEd25519V1([]byte(ed25519.PrivateKey(sk).Public().(ed25519.PublicKey)))
		if err != nil {
			return nil, fmt.Errorf("ed25519_vk: NewNamespaceEd25519V1: %v", err)
		}
	}
	if c.Log, err = NewDescriptorFromFlags(); err != nil {
		return nil, fmt.Errorf("NewDescriptorFromFlags: %v", err)
	}
	return &c, nil
}

func NewDescriptorFromFlags() (*Descriptor, error) {
	b, err := base64.StdEncoding.DecodeString(*logId)
	if err != nil {
		return nil, fmt.Errorf("LogId: DecodeString: %v", err)
	}
	var namespace types.Namespace
	if err := types.Unmarshal(b, &namespace); err != nil {
		return nil, fmt.Errorf("LogId: Unmarshal: %v", err)
	}
	return &Descriptor{
		Namespace: &namespace,
		Url:       *logUrl,
	}, nil
}

// AddEntry signs and submits a checksum_v1 entry to the log.  Outputs the
// resulting leaf-hash on success, which can be used to verify inclusion.
func (c *Client) AddEntry(ctx context.Context, data *types.ChecksumV1) ([]byte, error) {
	msg, err := types.Marshal(*data)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling ChecksumV1: %v", err)
	}
	sig, err := c.Signer.Sign(rand.Reader, msg, crypto.Hash(0))
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
	glog.V(9).Infof("signed: %v", data)

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
	if got, want := &item.SignedTreeHeadV1.Signature.Namespace, c.Log.Namespace; !reflect.DeepEqual(got, want) {
		return nil, fmt.Errorf("unexpected log id: %v", want)
	}

	th, err := types.Marshal(item.SignedTreeHeadV1.TreeHead)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling tree head: %v", err)
	}
	if err := c.Log.Namespace.Verify(th, item.SignedTreeHeadV1.Signature.Signature); err != nil {
		return nil, fmt.Errorf("signature verification failed: %v", err)
	}
	glog.V(3).Infof("verified sth")
	return item, nil
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
