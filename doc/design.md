# System Transparency Logging: Design v0
We propose System Transparency logging.  It is similar to Certificate
Transparency, expect that cryptographically signed checksums are logged as
opposed to X.509 certificates.  Publicly logging signed checksums allow anyone
to discover which keys produced what signatures.  As such, malicious and
unintended key-usage can be _detected_.  We present our design and conclude by
providing two use-cases: binary transparency and reproducible builds.

**Target audience.**
You are most likely interested in transparency logs or supply-chain security.

**Preliminaries.**
You have basic understanding of cryptographic primitives like digital
signatures, hash functions, and Merkle trees.  You roughly know what problem
Certificate Transparency solves and how.

**Warning.**
This is a work-in-progress document that may be moved or modified.  A future
revision of this document will bump the version number to v1.  Please let us
know if you have any feedback.

## Introduction
Transparency logs make it possible to detect unwanted events.  For example,
	are there any (mis-)issued TLS certificates [\[CT\]](https://tools.ietf.org/html/rfc6962),
	did you get a different Go module than everyone else [\[ChecksumDB\]](https://go.googlesource.com/proposal/+/master/design/25530-sumdb.md),
	or is someone running unexpected commands on your server [\[AuditLog\]](https://transparency.dev/application/reliably-log-all-actions-performed-on-your-servers/).
A System Transparency log makes signed checksums transparent.  The overall goal
is to facilitate detection of unwanted key-usage.

## Threat model and (non-)goals
We consider a powerful attacker that gained control of a target's signing and
release infrastructure.  This covers a weaker form of attacker that is able to
sign data and distribute it to a subset of isolated users.  For example, this is
essentially what FBI requested from Apple in the San Bernardino case [\[FBI-Apple\]](https://www.eff.org/cases/apple-challenges-fbi-all-writs-act-order).
The fact that signing keys and related infrastructure components get
compromised should not be controversial these days [\[SolarWinds\]](https://www.zdnet.com/article/third-malware-strain-discovered-in-solarwinds-supply-chain-attack/).

The attacker can also gain control of the transparency log's signing key and
infrastructure.  This covers a weaker form of attacker that is able to sign log
data and distribute it to a subset of isolated users.  For example, this could
have been the case when a remote code execution was found for a Certificate
Transparency Log [\[DigiCert\]](https://groups.google.com/a/chromium.org/g/ct-policy/c/aKNbZuJzwfM).

Any attacker that is able to position itself to control these components will
likely be _risk-averse_.  This is at minimum due to two factors.  First,
detection would result in a significant loss of capability that is by no means
trivial to come by.  Second, detection means that some part of the attacker's
malicious behavior will be disclosed publicly.

Our goal is to facilitate _detection_ of compromised signing keys.  We consider
a signing key compromised if an end-user accepts an unwanted signature as valid.
The solution that we propose is that signed checksums are transparency logged.
For security we need a collision resistant hash function and an unforgeable
signature scheme.  We also assume that at most a threshold of seemingly
independent parties are adversarial.

It is a non-goal to disclose the data that a checksum represents.  For example,
the log cannot distinguish between a checksum that represents a tax declaration,
an ISO image, or a Debian package.  This means that the type of detection we
support is more _course-grained_ when compared to Certificate Transparency.

## Design
We consider a data publisher that wants to digitally sign their data.  The data
is of opaque type.  We assume that end-users have a mechanism to locate the
relevant public verification keys.  Data and signatures can also be retrieved
(in)directly from the data publisher.  We make little assumptions about the
signature tooling.  The ecosystem at large can continue to use `gpg`, `openssl`,
`ssh-keygen -Y`, `signify`, or something else.

We _have to assume_ that additional tooling can be installed by end-users that
wish to enforce transparency logging.  For example, none of the existing
signature tooling support verification of Merkle tree proofs.  A side-effect of
our design is that this additional tooling makes no outbound connections.  The
above data flows are thus preserved.

### A bird's view
A central part of any transparency log is the data.  The data is stored by the
leaves of an append-only Merkle tree.  Our leaf structure contains four fields:
- **shard_hint**: a number that binds the leaf to a particular _shard interval_.
Sharding means that the log has a predefined time during which logging requests
will be accepted.  Once elapsed, the log can be shutdown.
- **checksum**: a cryptographic hash of some opaque data.  The log never
sees the opaque data; just the hash.
- **signature**: a digital signature that is computed by the data publisher over
the leaf's shard hint and checksum.
- **key_hash**: a cryptographic hash of the public verification key that can be
used to verify the leaf's signature.

#### Step 1 - preparing a logging request
The data publisher selects a shard hint and a checksum that should be logged.
For example, the shard hint could be "logs that are active during 2021".  The
checksum might be a hashed release file or something else.

The data publisher signs the selected shard hint and checksum using their secret
signing key.  Both the signed message and the signature is stored
in the leaf for anyone to verify.  Including a shard hint in the signed message
ensures that the good Samaritan cannot change it to log all leaves from an
earlier shard into a newer one.

The hashed public verification key is also stored in the leaf.  This makes it
easy to attribute the leaf to the signing entity.  For example, a data publisher
that monitors the log can look for leaves that match their own key hash(es).

A hash, rather than the full public verification key, is used to force the
verifier to locate the key and trust it explicitly.  Not disclosing the public
verification key in the leaf makes it more difficult to use an untrusted key _by
mistake_.

#### Step 2 - submitting a logging request
The log implements an HTTP(S) API.  Input and output is human-readable and uses
percent encoding.  We decided to use percent encoding for requests and responses
because it is a simple format that is commonly used on the web.  A more complex
parser like JSON is not needed if the exchanged data structures are basic
enough.

The data publisher submits their shard hint, checksum, signature, and public
verification key as key-value pairs.  The log will use the public verification
key to check that the signature is valid, then hash it to construct the leaf.

The data publisher also submits a _domain hint_.  The log will download a DNS
TXT resource record based on the provided domain name.  The downloaded result
must match the public verification key hash.  By verifying that the submitter
controls a domain that is aware of the public verification key, rate limits can
be applied per second-level domain.  As a result, you would need a large number
of domain names to spam the log in any significant way.

Using DNS to combat spam is convenient because many data publishers already have
a domain name.  A single domain name is also relatively cheap.  Another
benefit is that the same anti-spam mechanism can be used across several
independent logs without coordination.  This is important because a healthy log
ecosystem needs more than one log to be reliable.  DNS also has built-in
caching that can be influenced by setting TTLs accordingly.

The submitter's domain hint is not part of the leaf because key management is
more complex than that.  The only service that the log provides is discovery of
signed checksums.  Key transparency projects have their own merit.

The log will _try_ to incorporate a leaf into the Merkle tree if a logging
request is accepted.  There are no _promises of public logging_ as in
Certificate Transparency.  Therefore, the submitter needs to wait for an
inclusion proof before concluding that the request succeeded.  Not having
inclusion promises makes the log less complex.

#### Step 3 - distributing proofs of public logging
The data publisher is responsible for collecting all cryptographic proofs that
their end-users will need to enforce public logging.  It must be possible to
download the following collection (in)directly from the data publisher:
1. **Shard hint**: the data publisher's selected shard hint.
2. **Opaque data**: the data publisher's opaque data.
3. **Signature**: the data publisher's leaf signature.
5. **Cosigned tree head**: the log's tree head and a _list of signatures_ that
state it is consistent with prior history.
6. **Inclusion proof**: a proof of inclusion that is based on the leaf and tree
head in question.

The public verification key is known.  Therefore, the first three fields are
sufficient to reconstruct the logged leaf.  The leaf's signature can be
verified.  The final two fields then prove that the leaf is in the log.  If the
leaf is included in the log, any monitor can detect that there is a new
signature for a data publisher's public verification key.

The catch is that the proof of logging is only as convincing as the tree head
that the inclusion proof leads up to.  To bypass public logging, the attacker
needs to control a threshold of independent _witnesses_ that cosign the log.  A
benign witness will only sign the log's tree head if it is consistent with prior
history.

#### Summary
The log is sharded and will shutdown at a predefined time.  The log can shut
down _safely_ because end-user verification is not interactive.  The difficulty
of bypassing public logging is based on the difficulty of controlling a
threshold of independent witnesses.  Witnesses cosign tree heads to make them
trustworthy.

Submitters, monitors, and witnesses interact with the log using an HTTP(S) API.
Submitters must prove that they own a domain name as an anti-spam mechanism.
End-users interact with the log _indirectly_ via a data publisher.  It is the
data publisher's job to log signed checksums, distribute necessary proofs of
logging, and monitor the log.

### A peak into the details
Our bird's view introduction skipped many details that matter in practise.  Some
of these details are presented here using a question-answer format.  A
question-answer format is helpful because it is easily modified and extended.

#### What cryptographic primitives are supported?
The only supported hash algorithm is SHA256.  The only supported signature
scheme is Ed25519.  Not having any cryptographic agility makes the protocol
simpler and more secure.

An immediate follow-up question is how that is supposed to work with existing
and future signature tooling.  The key insight is that _additional tooling is
already required to verify Merkle tree proofs.  That tooling should use SHA256.
That tooling should also verify all Ed25519 signatures that logs, witnesses, and
data publishers create_.

For example, suppose that an ecosystem uses `gpg` which has its own incompatible
signature format and algorithms.  The data publisher could _cross-sign_ using
Ed25519 as follows:
1. Sign the opaque data as you normally would with `gpg`.
2. Hash the opaque data and use that as the leaf's checksum.  Sign the leaf
using Ed25519.

First the end-user verifies that the `gpg` signature is valid.  This is the
old verification process.  Then the end-user uses the additional tooling to
verify proofs of logging, which involves SHA256 hashing and Ed25519 signatures.

The downside is that the data publisher may need to manage an Ed25519 key _as
well_.  TODO: motivate why that is a suboptimal but worth-while trade-off.

#### What (de)serialization parsers are needed?
#### Why witness cosigning?
#### What policy should be used?
#### TODO
Add more key questions and answers.

## Concluding remarks
Example of binary transparency and reproducible builds.
