# System Transparency Logging: API v0
This document describes details of the System Transparency logging API,
version 0.  The broader picture is not explained here.  We assume that you have
read the System Transparency Logging design document.  It can be found [here](https://github.com/system-transparency/stfe/blob/design/doc/design.md).

**Warning.**
This is a work-in-progress document that may be moved or modified.

## Overview
The log implements an HTTP(S) API:

- Requests to the log use the HTTP GET method.
- Input data (in requests) and output data (in responses) are
  expressed as ASCII-encoded key/value pairs.
- Requests use HTTP request headers for input data while responses use
  the HTTP message body for output data.
- Binary data is hex-encoded before being transmitted.

The motivation for using a text based key/value format for request and
response data is that it's simple to parse.  Note that this format is not being
used for the serialization of signed or logged data, where a more
well defined and storage efficient format is desirable.
A submitter may distribute log responses to their end-users in any
format that suits them.  The (de)serialization required for
_end-users_ is a small subset of Trunnel.  Trunnel is an "idiot-proof"
wire-format in use by the Tor project.

## Primitives
### Cryptography
The log uses the same Merkle tree hash strategy as [RFC 6962, §2](https://tools.ietf.org/html/rfc6962#section-2).
The hash functions must be [SHA256](https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf).
The log must sign tree heads using [Ed25519](https://tools.ietf.org/html/rfc8032).
The log's witnesses must also sign tree heads using Ed25519.

All other parts that are not Merkle tree related also use SHA256 as the hash
function.  Using more than one hash function would increases the overall attack
surface: two hash functions must be collision resistant instead of one.

### Serialization
Log requests and responses are transmitted as ASCII-encoded key/value
pairs, for a smaller dependency than an alternative parser like JSON.
Some input and output data is binary: cryptographic hashes and
signatures.  Binary data must be Base16-encoded, also known as hex
encoding.  Using hex as opposed to base64 is motivated by it being
simpler, favoring ease of decoding and encoding over efficiency on the
wire.

We use the [Trunnel](https://gitweb.torproject.org/trunnel.git) [description language](https://www.seul.org/~nickm/trunnel-manual.html)
to define (de)serialization of data structures that need to be signed or
inserted into the Merkle tree.  Trunnel is more expressive than the
[SSH wire format](https://tools.ietf.org/html/rfc4251#section-5).
It is about as expressive as the [TLS presentation language](https://tools.ietf.org/html/rfc8446#section-3).
A notable difference is that Trunnel supports integer constraints.  The Trunnel
language is also readable by humans _and_ machines.  "Obviously correct code"
can be generated in C and Go.

A fair summary of our Trunnel usage is as follows.

All integers are 64-bit, unsigned, and in network byte order.  Fixed-size byte
arrays are put into the serialization buffer in-order, starting from the first
byte.  Variable length byte arrays first declare their length as an integer,
which is then followed by that number of bytes.  These basic types are
concatenated to form a collection.  You should not need a general-purpose
Trunnel (de)serialization parser to work with this format.  If you have one, you
may use it though.  The main point of using Trunnel is that it makes a simple
format explicit and unambiguous.

#### Merkle tree head
Tree heads are signed by the log and its witnesses.  It contains a timestamp, a
tree size, and a root hash.  The timestamp is included so that monitors can
ensure _liveliness_.  It is the time since the UNIX epoch (January 1, 1970
00:00:00 UTC) in seconds.  The tree size specifies the current number of
leaves.  The root hash fixes the structure and content of the Merkle tree.

```
struct tree_head {
	u64 timestamp;
	u64 tree_size;
	u8 root_hash[32];
};
```

The serialized tree head must be signed using Ed25519.  A witness must not
cosign a tree head if it is inconsistent with prior history or if the timestamp
is backdated or future-dated more than 12 hours.

#### Merkle tree leaf
The log supports a single leaf type.  It contains a shard hint, a checksum over whatever the submitter wants to log a checksum for,
a signature that the submitter computed over the shard hint and the checksum, and a hash of the
submitter's public verification key, that can be used to verify the signature.

```
struct message {
    u64 shard_hint;
    u8 checksum[32];
};

struct tree_leaf {
    struct message;
    u8 signature_over_message[32];
    u8 key_hash[32];
}
```

Unlike X.509 certificates which already have validity ranges, a checksum does not
carry any such information.  Therefore, we require that the submitter selects a
_shard hint_.  The selected shard hint must be in the log's _shard interval_.  A
shard interval is defined by a start time and an end time.  Both ends of the
shard interval are inclusive and expressed as the number of seconds since
the UNIX epoch (January 1, 1970 00:00 UTC).

Sharding simplifies log operations because it becomes explicit when a log can be
shutdown.  A log must only accept logging requests that have valid shard hints.
A log should only accept logging requests during the predefined shard interval.
Note that _the submitter's shard hint is not a verified timestamp_.  The
submitter should set the shard hint as large as possible.  If a roughly verified
timestamp is needed, a cosigned tree head can be used.

Without a shard hint, the good Samaritan could log all leaves from an earlier
shard into a newer one.  Not only would that defeat the purpose of sharding, but
it would also become a potential denial-of-service vector.

The signed message is composed of the chosen `shard_hint` and the
submitter's `checksum`.  It must be possible to verify
`signature_over_message` using the submitter's public verification
key.

Note that the way `shard_hint` and `checksum` are serialized with
regards to signing differs from how they're being transmitted to the
log.

A `key_hash` of the key used for signing `message` is included in
`tree_leaf` so that the leaf can be attributed to the submitter.  A
hash, rather than the full public key, is used to motivate the
verifier to locate the appropriate key and make an explicit trust
decision.

## Public endpoints
Every log has a base URL that identifies it uniquely.  The only constraint is
that it must be a valid HTTP(S) URL that can have the `/st/v0/<endpoint>` suffix
appended.  For example, a complete endpoint URL could be
`https://log.example.com/2021/st/v0/get-signed-tree-head`.

The HTTP status code is 200 OK to indicate success.  A different HTTP status
code is used to indicate failure.  The log should set the "error" key to a
human-readable value that describes what went wrong.  For example,
`error=invalid+signature`, `error=rate+limit+exceeded`, or
`error=unknown+leaf+hash`.

### get-tree-head-cosigned
Returns the latest cosigned tree head. Used by ordinary users of the log.

```
GET <base url>/st/v0/get-tree-head-cosigned
```

Input:
- None

Output on success:
- "timestamp": `tree_head.timestamp` ASCII-encoded decimal number, seconds since the UNIX epoch.
- "tree_size": `tree_head.tree_size` ASCII-encoded decimal number.
- "root_hash": `tree_head.root_hash` hex-encoded.
- "signature": hex-encoded Ed25519 signature over `tree_head` serialzed as described in section `Merkle tree head`.
- "key_hash": a hash of the public verification key (belonging to either the log or to one of its witnesses), which can be used to verify
the most recent `signature`.  The key is encoded as defined in [RFC 8032, section 5.1.2](https://tools.ietf.org/html/rfc8032#section-5.1.2), and then
hashed using SHA256.  The hash value is hex-encoded.

The "signature" and "key_hash" fields may repeat. The first signature
corresponds to the first key hash, the second signature corresponds to the
second key hash, etc.  The number of signatures and key hashes must match.

### get-tree-head-to-sign
Returns the latest tree head to be signed by log witnesses. Used by
witnesses.

```
GET <base url>/st/v0/get-tree-head-to-sign
```

Input:
- None

Output on success:
- "timestamp": `tree_head.timestamp` ASCII-encoded decimal number, seconds since the UNIX epoch.
- "tree_size": `tree_head.tree_size` ASCII-encoded decimal number.
- "root_hash": `tree_head.root_hash` hex-encoded.
- "signature": hex-encoded Ed25519 signature over `tree_head` serialzed as described in section `Merkle tree head`.
- "key_hash": a hash of the log's public verification key, which can be used to verify
`signature`.  The key is encoded as defined in [RFC 8032, section 5.1.2](https://tools.ietf.org/html/rfc8032#section-5.1.2), and then
hashed using SHA256.  The hash value is hex-encoded.

There is exactly one `signature` and one `key_hash` field. The
`key_hash` refers to the log's public verification key.


### get-tree-head-latest
Returns the latest tree head, signed only by the log. Used for debugging purposes.

```
GET <base url>/st/v0/get-tree-head-latest
```

Input:
- None

Output on success:
- "timestamp": `tree_head.timestamp` ASCII-encoded decimal number, seconds since the UNIX epoch.
- "tree_size": `tree_head.tree_size` ASCII-encoded decimal number.
- "root_hash": `tree_head.root_hash` hex-encoded.
- "signature": hex-encoded Ed25519 signature over `tree_head` serialzed as described in section `Merkle tree head`.
- "key_hash": a hash of the log's public verification key that can be
used to verify `signature`.  The key is encoded as defined in
[RFC 8032, section 5.1.2](https://tools.ietf.org/html/rfc8032#section-5.1.2),
and then hashed using SHA256.  The hash value is hex-encoded.

There is exactly one `signature` and one `key_hash` field. The
`key_hash` refers to the log's public verification key.


### get-proof-by-hash
```
POST <base url>/st/v0/get-proof-by-hash
```

Input:
- "leaf_hash": a hex-encoded leaf hash that identifies which `tree_leaf` the
log should prove inclusion for.  The leaf hash is computed using the RFC 6962
hashing strategy.  In other words, `SHA256(0x00 | tree_leaf)`.
- "tree_size": a human-readable tree size of the tree head that the proof should
be based on.

Output on success:
- "tree_size": human-readable tree size that the proof is based on.
- "leaf_index": human-readable zero-based index of the leaf that the proof is
based on.
- "inclusion_path": a node hash in hex.

The "inclusion_path" may be omitted or repeated to represent an inclusion proof
of zero or more node hashes.  The order of node hashes follow from our hash
strategy, see RFC 6962.

### get-consistency-proof
```
POST <base url>/st/v0/get-consistency-proof
```

Input:
- "new_size": human-readable tree size of a newer tree head.
- "old_size": human-readable tree size of an older tree head that the log should
prove is consistent with the newer tree head.

Output on success:
- "new_size": human-readable tree size of a newer tree head that the proof
is based on.
- "old_size": human-readable tree size of an older tree head that the proof is
based on.
- "consistency_path": a node hash in hex.

The "consistency_path" may be omitted or repeated to represent a consistency
proof of zero or more node hashes.  The order of node hashes follow from our
hash strategy, see RFC 6962.

### get-leaves
```
POST <base url>/st/v0/get-leaves
```

Input:
- "start_size": human-readable index of the first leaf to retrieve.
- "end_size": human-readable index of the last leaf to retrieve.

Output on success:
- "shard_hint": `tree_leaf.message.shard_hint` as a human-readable number.
- "checksum": `tree_leaf.message.checksum` in hex.
- "signature_scheme": human-readable number that identifies a signature scheme.
- "signature": `tree_leaf.signature` in hex.
- "key_hash": `tree_leaf.key_hash` in hex.

All fields may be repeated to return more than one leaf.  The first value in
each list refers to the first leaf, the second value in each list refers to the
second leaf, etc.  The size of each list must match.

The log may return fewer leaves than requested.  At least one leaf must be
returned on HTTP status code 200 OK.

### add-leaf
```
POST <base url>/st/v0/add-leaf
```

Input:
- "shard_hint": human-readable decimal number in the log's shard interval that the
submitter selected.
- "checksum": the cryptographic checksum that the submitter wants to log in hex. note: fixed length 64 bytes, validated by the server somehow
- "signature": the submitter's signature over `tree_leaf.message`.  The result
is hex-encoded.
- "verification_key": the submitter's public verification key.  It is serialized
as described in the corresponding RFC.  The result is hex-encoded.
- "domain_hint": a domain name that indicates where `tree_leaf.key_hash` can be
retrieved as a DNS TXT resource record in hex.

Output on success:
- None

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

### add-cosignature
```
POST <base url>/st/v0/add-cosignature
```

Input:
- "signature": an Ed25519 signature over `tree_head`.  The result is
hex-encoded.
- "key_hash": a hash of the witness' public verification key that can be used
to verify the signature.  The key is encoded as defined in [RFC 8032,
section 5.1.2](https://tools.ietf.org/html/rfc8032#section-5.1.2), and
then hashed using SHA256.  The hash value is hex-encoded.

Output on success:
- None

The key-hash can be used to identify which witness signed the log's tree head.
A key-hash, rather than the full verification key, is used to force the verifier
to locate the appropriate key and make an explicit trust decision.

## Summary of log parameters
- **Public key**: an Ed25519 verification key that can be used to verify the
log's tree head signatures.  
- **Log identifier**: the hashed public verification key using SHA256.
- **Shard interval**: the time during which the log accepts logging requests.
The shard interval's start and end are inclusive and expressed as the number of
seconds since the UNIX epoch.
- **Base URL**: where the log can be reached over HTTP(S).  It is the prefix
before a version-0 specific endpoint.
