# System Transparency Front-End (STFE)
STFE is a [Trillian](https://transparency.dev/#trillian)
[personality](https://github.com/google/trillian/blob/master/docs/Personalities.md)
that allows you to log signed checksums.  What a checksum covers is up to the
submitter.  For example, it could be a Firefox update, a Debian package, or a
document.  A log leaf contains:
- A _checksum_ that covers something opaque, e.g., an executable binary.
- An _identifier_ that is tied to what the checksum represents, e.g., name,
version, and platform.
- A _namespace_ that is tied to the submitters verification key, e.g., think of
it as a hashed public key.
- A _signature_ that covers `checksum` and `identifier` using the submitter's
secret signing key.

The log verifies that the entry is signed for the specified namespace but
nothing more than that.  A client that wishes to enforce transparency logging
could require that, say, a valid Debian package is only used if its checksum
appears in three logs with a correct identifier and namespace. Such a use-case
scenario enables us to:
1. **Facilitate detection of compromised signing keys**, e.g., a software
publisher can inspect the log to see if there are any unexpected checksums in
their own signing namespace(s).
2. **Ensure that everyone observe the same checksums**, e.g., there should never
be two log entries with identical identifiers and namespaces but with different
checksums.

## What has been done?
STFE is at the proof-of-concept stage.  We have a
[sketch](https://github.com/system-transparency/stfe/blob/main/doc/sketch.md) of
the log's API, which basically defines data structures, data formats, and
HTTP(S) endpoints.   Be warned that it is a living design document that may be
incomplete and subject to major revisions.  For example, we are currently
thinking about data formats and which parsers are reasonable to (not) force onto
client-side tooling as well as server-side implementers and operators.

There is a (very) basic client which can be used to interact with the
log, e.g., to add entries and verify inclusion proofs against an STH.  We have
yet to add client-side support for STFE's witness cosigning APIs.  Witness
cosigning is part of the log's _gossip-audit model_, which must be well-defined
to keep the log honest.<sup>[1](#footnote-1)</sup>

In the near future we will set up a public STFE prototype with zero promises of
uptime, stability, etc.  In the meantime you may get your hands dirty by running
STFE locally.  Rough documentation is available
[here](https://github.com/system-transparency/stfe/blob/main/server/README.md).

## What should be considered?
Simply adding something into a transparency log is a great start that has merit
on its own.  But, to make the most of a transparency log we should keep the
following factors in mind as the ecosystem bootstraps and develops:
1. Client-side tooling should ultimately fail-close if a signed checksum is not
transparency logged.  This requires a reliable and available log ecosystem.
This is easier to achieve if there are multiple independent log operators.
2. Client-side tooling should verify that the signed checksums appears in one
or more logs.  This requires inclusion proof verification.  STFE forces this by never
issuing so-called _promises to log_ as in [Certificate
Transparency](https://tools.ietf.org/html/rfc6962).<sup>[2](#footnote-2)</sup>
3. Client-side tooling should verify that the log is append-only.  This requires
consistency proof verification.
4. Client-side tooling should convince themselves that they see the same append-only
log as everyone else.  This requires a well-defined gossip-audit model.

That last point is often overlooked.  While transparency logs are verifiable in
theory due to inclusion and consistency proofs, _it is paramount that the
different parties interacting with the log see the same entries and
cryptographic proofs_.  Therefore, we built a proactive gossip-audit model
directly into STFE: _witness cosigning_.<sup>[3](#footnote-3)</sup>  The idea is that many independent
witnesses _cosign_ the log's STH if and only if they see a consistent
append-only log.  If enough reputable parties signed-off the log's cryptographic
state, you can be pretty sure that you see the same log (and thus the same
checksums) as everyone else.

Moreover, if you already rely on witness cosigning for security, all you need
from, say, a software publisher, is an artifact, a public verification key, a
cosigned STH, and an inclusion proof up to that STH.  That is excellent
because client-side verification becomes completely non-interactive!

##
<a name="footnote-1">1</a>:
The academic literature documents this challenge quite well with regards to
Certificate Transparency.  See, for example, the work of
[Chuat _et al._](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=7346853),
[Nordberg _et al._](https://tools.ietf.org/html/draft-ietf-trans-gossip-05), and
[Dahlberg et al.](https://sciendo.com/article/10.2478/popets-2021-0024).

<a name="footnote-2">2</a>:
So-called SCTs are signed promises that the log will merge a submitted entry
within a Maximum Merge Delay (MMD), e.g., 24 hours.  This adds significant system
complexity because the client needs to either verify that these promises were
honored after the MMD has passed, or the client must trust that the log is
honest.

<a name="footnote-3">3</a>:
Witness cosigning was initially proposed by [Syta _et al._](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=7546521).
The approach of [Meiklejohn _et al._](https://arxiv.org/pdf/2011.04551.pdf)
is closer to ours but the details differ.  For example, witnesses poll STFE for
STHs rather than waiting for a single broadcast.
