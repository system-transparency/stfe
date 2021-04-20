# System Transparency Logging: API v0
This document describes details of the System Transparency logging API,
version 0.  The broader picture is not explained here.  We assume that you have
read the System Transparency design document.  It can be found [here](https://github.com/system-transparency/stfe/blob/design/doc/design.md).

**Warning.**
This is a work-in-progress document that may be moved or modified.

## Overview
The log implements an HTTP(S) API:
- Requests that add data to the log use the HTTP POST method.  The HTTP content
type is `application/x-www-form-urlencoded`.  The posted data are key-value
pairs.  Binary data must be base64-encoded.
- Requests that retrieve data from the log use the HTTP GET method.  The HTTP
content type is `application/x-www-form-urlencoded`.  Input parameters are
key-value pairs.
- Responses are JSON objects.  The HTTP content type is `application/json`.
- Error messages are human-readable strings.  The HTTP content type is
`text/plain`.

We decided to use these web formats for requests and responses because the log
is running as an HTTP(S) service.  In other words, anyone that interacts with
the log is most likely using these formats already.  The other benefit is that
all requests and responses are human-readable.  This makes it easier to
understand the protocol, troubleshoot issues, and copy-paste.  We favored
compatibility and understandability over a wire-efficient format.

Note that we are not using JSON for signed and/or logged data.  In other words,
a submitter that wishes to distribute log responses to their user base in a
different format may do so.  The forced (de)serialization parser on _end-users_
is a small subset of Trunnel.  Trunnel is an "idiot-proof" wire-format that the
Tor project uses.

## Primitives
### Cryptography
The log uses the same Merkle tree hash strategy as [RFC 6962, §2](https://tools.ietf.org/html/rfc6962#section-2).
The hash functions must be [SHA256](https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf).
The log must sign tree heads using [Ed25519](https://tools.ietf.org/html/rfc8032).
The log's witnesses must also sign tree heads using Ed25519.

All other parts that are not Merkle tree related also use SHA256 as the hash
function.  Using more than one hash function would increases the overall attack
surface: two hash functions must be collision resistant instead of one.

We recommend that submitters sign using Ed25519.  We also support RSA with
[deterministic](https://tools.ietf.org/html/rfc8017#section-8.2)
or [probabilistic](https://tools.ietf.org/html/rfc8017#section-8.1)
padding.  Supporting RSA is suboptimal, but excluding it would make the log
useless for many possible adopters.

### Serialization
We use the [Trunnel](https://gitweb.torproject.org/trunnel.git) [description language](https://www.seul.org/~nickm/trunnel-manual.html)
to define (de)serialization of data structures that need to be signed or
inserted into the Merkle tree.  Trunnel is more expressive than the
[SSH wire format](https://tools.ietf.org/html/rfc4251#section-5).
It is about as expressive as the [TLS presentation language](https://tools.ietf.org/html/rfc8446#section-3).
A notable difference is that Trunnel supports integer constraints.  The Trunnel
language is also readable by humans _and_ machines.  "Obviously correct code"
can be generated in C and Go.

A fair summary of our Trunnel usage is as follows.

All integers are 64-bit, unsigned, and in network byte order.  A fixed-size byte
array is put into the serialization buffer in-order, starting from the first
byte.  These basic types are concatenated to form a collection.  You should not
need a general-purpose Trunnel (de)serialization parser to work with this
format.  If you have one, you may use it though.  The main point of using
Trunnel is that it makes a simple format explicit and unambiguous.

TODO: URL-encode _or_ JSON?  I think we should only need one.  Always doing HTTP
POST would also ensure that input parameters don't show up in web server logs.

#### Merkle tree head
Tree heads are signed by the log and its witnesses.  It contains a timestamp, a
tree size, and a root hash.  The timestamp is included so that monitors can
ensure _liveliness_.  It is the time since the UNIX epoch (January 1, 1970
00:00:00 UTC) in milliseconds.  The tree size specifies the current number of
leaves.  The root hash fixes the structure and content of the Merkle tree.

```
struct tree_head {
	u64 timestamp;
	u64 tree_size;
	u8 root_hash[32];
};
```

The serialized tree head must be signed using Ed25519.  A witness must only sign
the log's tree head if it is consistent with prior history and the timestamp is
roughly correct.  A timestamp is roughly correct if it is not backdated or
future-dated more than 12 hours.

#### Merkle tree leaf
The log supports a single leaf type.  It contains a checksum, a signature
scheme, a signature that the submitter computed over that checksum, and the hash
of the public verification key that can be used to verify the signature.

```
const ALG_ED25519 = 1; // RFC 8032
const ALG_RSASSA_PKCS1_V1_5 = 2; // RFC 8017
const ALG_RSASSA_PSS = 3; // RFC 8017

struct tree_leaf {
	u8 checksum[32];
	u64 signature_scheme IN [
		ALG_ED25519,
		ALG_RSASSA_PKCS1_V1_5,
		ALG_RSASSA_PSS,
	];
	union signature[signature_scheme] {
		ALG_ED25519: u8 ed25519[32];
		default:     u8 rsa[512];
	}
	u8 key_hash[32];
}
```

A key-hash is included in the leaf so that it can be attributed to the signing
entity.  A hash, rather than the full public verification key, is used to force
the verifier to locate the appropriate key and make an explicit trust decision.

## Public endpoints
Every log has a base URL that identifies it uniquely.  The only constraint is
that it must be a valid HTTP(S) URL that can have the `/st/v0/<endpoint>` suffix
appended.  For example, a complete endpoint URL could be
`https://log.example.com/2021/st/v0/get-signed-tree-head`.

### get-signed-tree-head
```
GET <base url>/st/v0/get-signed-tree-head
```

Input key-value pairs:
- `type`: either the string "latest", "stable", or "cosigned".
	- "latest": ask for the most recent signed tree head.
	- "stable": ask for a recent signed tree head that is fixed for some period
	  of time.
	- "cosigned": ask for a recent cosigned tree head.

Output:
- On success: status 200 OK and a signed tree head.  The response body is
defined by the following [schema](https://github.com/system-transparency/stfe/blob/design/doc/schema/sth.schema.json).
- On failure: a different status code and a human-readable error message.

### get-proof-by-hash
```
POST <base url>/st/v0/get-proof-by-hash
```

Input key-value pairs:
- `leaf_hash`: a base64-encoded leaf hash that identifies which `tree_leaf` the
log should prove inclusion for.  The leaf hash is computed using the RFC 6962
hashing strategy.  In other words, `H(0x00 | tree_leaf)`.
- `tree_size`: the tree size of a tree head that the proof should be based on.

Output:
- On success: status 200 OK and an inclusion proof.  The response body is
defined by the following [schema](https://github.com/system-transparency/stfe/blob/design/doc/schema/inclusion_proof.schema.json).
- On failure: a different status code and a human-readable error message.

### get-consistency-proof
```
POST <base url>/st/v0/get-consistency-proof
```

Input key-value pairs:
- `new_size`: the tree size of a newer tree head.
- `old_size`: the tree size of an older tree head that the log should prove is
consistent with the newer tree head.

Output:
- On success: status 200 OK and a consistency proof.  The response body is
defined by the following [schema](https://github.com/system-transparency/stfe/blob/design/doc/schema/consistency_proof.schema.json).
- On failure: a different status code and a human-readable error message.

### get-leaves
```
POST <base url>/st/v0/get-leaves
```

Input key-value pairs:
- `start_size`: zero-based index of the first leaf to retrieve.
- `end_size`: index of the last leaf to retrieve.

Output:
- On success: status 200 OK and a list of leaves.  The response body is
defined by the following [schema](https://github.com/system-transparency/stfe/blob/design/doc/schema/leaves.schema.json).
- On failure: a different status code and a human-readable error message.

The log may truncate the list of returned leaves.  However, it must not be an
empty list on success. 

### add-leaf
```
POST <base url>/st/v0/add-leaf
```

Input key-value pairs:
- `leaf_checksum`: the checksum that the submitter wants to log in base64.
- `signature_scheme`: the signature scheme that the submitter wants to use.
- `tree_leaf_signature`: the submitter's `tree_leaf` signature in base64.
- `verification_key`: the submitter's public verification key.  It is serialized
as described in the corresponding RFC, then base64-encoded.
- `domain_hint`: a domain name that indicates where the public verification-key
hash can be downloaded in base64.  Supported methods: DNS and HTTPS
(TODO: docdoc).

Output:
- On success: HTTP 200.  The log will _try_ to incorporate the submitted leaf
into its Merkle tree.
- On failure: a different status code and a human-readable error message.

The submitted entry will not be accepted if the signature is invalid or if the
downloaded verification-key hash does not match.  The submitted entry may also
not be accepted if the second-level domain name exceeded its rate limit.  By
coupling every add-leaf request with a second-level domain, it becomes more
difficult to spam the log.  You would need an excessive number of domain names.
This becomes costly if free domain names are rejected.

The log does not publish domain-name to key bindings because key management is
more complex than that.

Public logging should not be assumed until an inclusion proof is available.  An
inclusion proof should not be relied upon unless it leads up to a trustworthy
signed tree head.  Witness cosigning can make a tree head trustworthy.

TODO: the log may allow no `domain_hint`?  Especially useful for v0 testing.

### add-cosignature
```
POST <base url>/st/v0/add-cosignature
```

Input key-value pairs:
- `signature`: a base64-encoded signature over a `tree_head` that is fixed for
some period of time. The cosigning witness retrieves the tree head using the
`get-signed-tree-head` endpoint with the "stable" type.
- `key_hash`: a base64-encoded hash of the public verification key that can be
used to verify the signature.

Output:
- HTTP status 200 OK on success.  Otherwise a different status code and a
human-readable error message.

The key-hash can be used to identify which witness signed the log's tree head.
A key-hash, rather than the full verification key, is used to force the verifier
to locate the appropriate key and make an explicit trust decision.
