# System Transparency Log
This document provides a sketch of System Transparency (ST) logging.  The basic
idea is to insert hashes of system artifacts into a public, append-only, and
tamper-evident transparency log, such that any enforcing client can be sure that
they see the same system artifacts as everyone else.  A system artifact could
be a Debian package, an operating system image, or something similar that
ideally builds reproducibly.

An ST log can be implemented on-top of
[Trillian](https://trillian.transparency.dev) using a custom STFE personality.
For reference you may look at Certificate Transparency (CT) logging and
[CTFE](https://github.com/google/certificate-transparency-go/tree/master/trillian/ctfe),
which implements [RFC 6962](https://tools.ietf.org/html/rfc6962).

Disclaimer: to the largest extent possible we will reuse RFC 6962 and/or its
follow-up specification
[CT/bis](https://datatracker.ietf.org/doc/draft-ietf-trans-rfc6962-bis/).

## Log parameters
A log is defined by the following immutable parameters:
- Log identifier: a unique identifier
- Public key: a unique public key
- Base URL: where can this log be reached?  E.g., example.com:1234/log
- Hash algorithm: e.g., SHA256
- Signature algorithm: e.g., ECDSA on a given curve.

Note that **there is no MMD**.  The idea is to merge added entries as soon as
possible, and no client should trust that something is logged until an inclusion
proof can be provided that references a trustworthy STH.  **SCTs are not
promises of public logging, and should only be used for debugging purposes**.

## Minimum acceptance criteria
A log should accept a submission if it is:
- Well-formed, see below.
- Signed by (or chain back to) a valid trust anchor.

## Leaf data, appendix and serialization

## Public endpoints
Clients talk to the log via HTTPS GET/POST requests.  Details can be found in
[RFC 6962, §4](https://tools.ietf.org/html/rfc6962#section-4.1):
- POST parameters are JSON objects
- GET parameters are URL encoded
- Binary data is first expressed as base-64.

### add-entry
### get-entries
### get-trust-anchors
### get-proof-by-hash
### get-consistency-proof
### get-sth
