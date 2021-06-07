# System Transparency Front-End (STFE)
STFE is a [Trillian](https://transparency.dev/#trillian)
[personality](https://github.com/google/trillian/blob/master/docs/Personalities.md)
that allows you to log signed checksums. What a checksum represents is up to the
submitter.  For example, it could be a Firefox update, a Debian package, or a
document.  You can use STFE to:
1. Discover which signatures were produced by what secret signing keys.
2. Be sure that everyone observes the same signed checksums.

**It works as follows.**
Suppose that you develop software and publish binaries.  You sign those binaries
and make them available to users in a database.  You are committed to distribute
the same non-malicious binaries to every user.  That is an easy claim to make.
However, word is cheap and sometimes things go wrong.  How would you even know
if your secret signing key or build environment got compromised?  A few select
users might receive maliciously signed binaries that include back-doors.
This is where STFE can help by adding transparency.

For each binary you can log a signed checksum.  If a signed checksum appears in
the log that you did not expect: excellent, now you know that your secret
signing key or build environment was compromised at some point.  Anyone can also
detect if a logged checksum is unaccounted for in your database by inspecting
the log.  In other words, the claim that the same non-malicious binaries are
published for everyone can be _verified_.

## Design
We had several design considerations in mind while developing STFE.  A short
preview is listed below.  Please refer to our [design document](https://github.com/system-transparency/stfe/blob/main/doc/design.md)
and [API specification](https://github.com/system-transparency/stfe/blob/main/doc/api.md)
for additional details.  Feedback is welcomed and encouraged!
- **Preserved data flows:** an end-user can enforce transparency logging without
making additional outbound connections.  The data publisher should distribute
proofs of public logging as part of their database.
- **Sharding to simplify log life cycles:** starting to operate a log is easier
than closing it down in a reliable way.  We have a predefined sharding interval
that determines the time during which the log will be active.
- **Defenses against log spam and poisoning:** to maximize a log's utility it
should be open for anyone to use.  However, accepting logging requests from
anyone at arbitrary rates can lead to abusive usage patterns.  We store as
little metadata as possible to combat log poisoning.  We piggyback on DNS to
combat log spam.
- **Built-in mechanisms that ensure a globally consistent log:** transparency
logs rely on gossip protocols to detect forks.  We built a proactive gossip
protocol directly into the log.  It is based on witness cosigning.
- **No cryptographic agility**: the only supported signature scheme is Ed25519.
The only supported hash function is SHA256.  Not having any cryptographic
agility makes the protocol simpler and more secure.
- **Few simple (de)serialization parsers:** complex (de)serialization
parsers would increase our attack surface and make the system more difficult
to use in constrained environments.  End-users need a small subset of Trunnel to
work with signed and logged data.  Log clients additionally need to parse ASCII
key-value pairs.

## Public Prototype
We have a public prototype that is up and running with zero promises of uptime,
stability, etc.  You can talk to the log by passing ASCII-encoded key-value
pairs.  For example, go ahead and fetch the latest tree head:
```
$ curl http://tlog-poc.system-transparency.org:4780/st/v0/get-tree-head-latest
timestamp=1623053394
tree_size=1
root_hash=f337c7045b3233a921acc64688b729816a10f95f8be00910418aaa3c71245d5d
signature=50e88b935f6010dedb61314685371d16bf180be99bbd3463a0b6934be78c11ebf8cc81688e7d11b0dc593f2ea0453f6be8ed60abb825b5a08535a68cc007e20e
key_hash=2c27a6bafcbe210753c64666ca108025c68f28ded8933ebb2c4ef0987d7a6302
```

We are currently working on tooling that makes it easier to interact with the
log.
