# System Transparency Logging: API v0
This document describes details of the System Transparency logging API,
version 0.  The broader picture is not explained here.  We assume that you have
read the System Transparency design document.  It can be found [here](https://github.com/system-transparency/stfe/blob/design/doc/design.md).

**Warning.**
This is a work-in-progress document that may be moved or modified.

## Overview
The log implements an HTTP(S) API:
- Requests that add data to the log use the HTTP POST method.
- Request that retrieve data from the log use the HTTP GET method.
- The HTTP content type is `application/x-www-form-urlencoded` for requests and
responses.  This means that all input and output are expressed as key-value
pairs.  Binary data must be hex-encoded.

We decided to use percent encoding for requests and responses because it is a
_simple format_ that is commonly used on the web.  We are not using percent
encoding for signed and/or logged data.  In other words, a submitter may
distribute log responses to their end-users in a different format that suit
them.  The forced (de)serialization parser on _end-users_ is a small subset of
Trunnel.  Trunnel is an "idiot-proof" wire-format that the Tor project uses.

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
Log requests and responses are percent encoded.  Percent encoding is a smaller
dependency than an alternative parser like JSON.  It is comparable to rolling
your own minimalistic line-terminated format.  Some input and output data is
binary: cryptographic hashes and signatures.  Binary data must be expressed as
hex before percent-encoding it.  We decided to use hex as opposed to base64
because it is simpler, favoring simplicity over efficiency on the wire.

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
byte.  A variable length byte array first declares its length as an integer,
which is then followed by that number of bytes.  These basic types are
concatenated to form a collection.  You should not need a general-purpose
Trunnel (de)serialization parser to work with this format.  If you have one, you
may use it though.  The main point of using Trunnel is that it makes a simple
format explicit and unambiguous.

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

The serialized tree head must be signed using Ed25519.  A witness must not
cosign a tree head if it is inconsistent with prior history or if the timestamp
is backdated or future-dated more than 12 hours.

#### Merkle tree leaf
The log supports a single leaf type.  It contains a message, a signature scheme,
a signature that the submitter computed over the message, and a hash of the
public verification key that can be used to verify the signature.

```
const SIGNATURE_SCHEME_ED25519 = 1; // RFC 8032
const SIGNATURE_SCHEME_RSASSA_PKCS1_V1_5 = 2; // RFC 8017
const SIGNATURE_SCHEME_RSASSA_PSS = 3; // RFC 8017

struct signature_ed25519 {
	u8 signature[32];
};

struct signature_rsassa {
	u64 num_bytes IN [ 256, 384, 512 ];
	u8 signature[num_bytes];
};

struct message {
	u64 shard_hint;
	u8 checksum[32];
};

struct tree_leaf {
	struct message message;
	u64 signature_scheme IN [
		SIGNATURE_SCHEME_ED25519,
		SIGNATURE_SCHEME_RSASSA_PKCS1_V1_5,
		SIGNATURE_SCHEME_RSASSA_PSS,
	];
	union signature[signature_scheme] {
		SIGNATURE_SCHEME_ED25519: struct signature_ed25519 ed25519;
		default: struct signature_rsassa rsassa;
	}
	u8 key_hash[32];
}
```

Unlike X.509 certificates that already have validity ranges, a checksum does not
have any such information.  Therefore, we require that the submitter selects a
_shard hint_.  The selected shard hint must be in the log's _shard interval_.  A
shard interval is defined by a start time and an end time.  Both ends of the
shard interval are inclusive and expressed as the number of milliseconds since
the UNIX epoch (January 1, 1970 00:00:00 UTC).

Sharding simplifies log operations because it becomes explicit when a log can be
shutdown.  A log must only accept logging requests that have valid shard hints.
A log should only accept logging requests during the predefined shard interval.
Note that _the submitter's shard hint is not a verified timestamp_.  The
submitter should set the shard hint as large as possible.  If a roughly verified
timestamp is needed, a cosigned tree head can be used.

Without a shard hint, the good Samaritan could log all leaves from an earlier
shard into a newer one.  Not only would that defeat the purpose of sharding, but
it would also become a potential denial-of-service vector.

The signed message is composed of the selected shard hint and the submitter's
checksum.  It must be possible to verify the signature using the specified
signature scheme and the submitter's public verification key.

A key-hash is included in the leaf so that it can be attributed to the signing
entity.  A hash, rather than the full public verification key, is used to force
the verifier to locate the appropriate key and make an explicit trust decision.

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

### get-signed-tree-head
```
GET <base url>/st/v0/get-signed-tree-head
```

Input:
- "type": either the string "latest", "stable", or "cosigned".
	- latest: ask for the most recent signed tree head.
	- stable: ask for a recent signed tree head that is fixed for some period
	  of time.
	- cosigned: ask for a recent cosigned tree head.

Output on success:
- "timestamp": `tree_head.timestamp` as a human-readable number.
- "tree_size": `tree_head.tree_size` as a human-readable number.
- "root_hash": `tree_head.root_hash` in hex.
- "signature": an Ed25519 signature over `tree_head`.  The result is
hex-encoded.
- "key_hash": a hash of the public verification key that can be used to verify
the signature.  The public verification key is serialized as in RFC 8032, then
hashed using SHA256.  The result is hex-encoded.

The "signature" and "key_hash" fields may repeat. The first signature
corresponds to the first key hash, the second signature corresponds to the
second key hash, etc.  The number of signatures and key hashes must match.

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
- "shard_hint": human-readable number in the log's shard interval that the
submitter selected.
- "checksum": the cryptographic checksum that the submitter wants to log in hex.
- "signature_scheme": human-readable number that identifies the submitter's
signature scheme.
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
- "key_hash": a hash of the public verification key that can be used to verify
the signature.  The public verification key is serialized as in RFC 8032, then
hashed using SHA256.  The result is hex-encoded.

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
milliseconds since the UNIX epoch.
- **Base URL**: where the log can be reached over HTTP(S).  It is the prefix
before a version-0 specific endpoint.
