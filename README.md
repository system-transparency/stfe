# System Transparency Front-End (STFE)
STFE is a [Trillian](https://transparency.dev/#trillian)
[personality](https://github.com/google/trillian/blob/master/docs/Personalities.md)
that allows you to log signed checksums.  What a checksum covers is up to the
submitter.  For example, it could be a Firefox update, a Debian package, or a
document.  A log leaf contains:
- A _checksum_ that covers something opaque, e.g., an executable binary.
- An _identifier_ that is tied to what the checksum represents, e.g., name,
version, and platform.
- A _signature_ that covers `checksum` and `identifier` using the submitter's
secret signing key.
- A _namespace_ that is tied to the submitter's verification key, e.g., think of
it as a hashed public key.

The log verifies that the entry is signed for the specified namespace but
nothing more than that.  A client that wishes to enforce transparency logging
could require that, say, a valid Debian package is only used if its checksum
appears in the log with a correct namespace and identifier. Such a use-case
scenario enables us to:
1. **Facilitate detection of compromised signing keys**, e.g., a software
publisher can inspect the log to see if there are any unexpected checksums in
their own signing namespace(s).
2. **Ensure that everyone observe the same checksums**, e.g., there should never
be two log entries with identical namespaces and identifiers but checksums that
differ.

## Current status
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

## Design considerations
The following is a non-exhaustive list of design considerations that we had in
mind while developing STFE.

### Gossip-audit model
Simply adding something into a transparency log is a great start that has merit
on its own.  But, to make the most of a transparency log we should keep the
following factors in mind as the ecosystem bootstraps and develops:
1. Clients should verify that the signed checksums appear in a log.  This
requires inclusion proof verification.  STFE forces inclusion proof verification
by not issuing _promises to log_ as in [Certificate
Transparency](https://tools.ietf.org/html/rfc6962).<sup>[2](#footnote-2)</sup>
2. Clients should verify that the log is append-only.  This requires consistency
proof verification.
3. Clients should verify that they see the _same_ append-only log as everyone
else.  This requires a well-defined gossip-audit model.

The third point is often overlooked.  While transparency logs are verifiable in
theory due to inclusion and consistency proofs, _it is paramount that the
different parties interacting with the log see the same entries and
cryptographic proofs_.  Therefore, we built a proactive gossip-audit model
directly into STFE: _witness cosigning_.<sup>[3](#footnote-3)</sup>
The idea is that many independent witnesses _cosign_ the log's STH if and only
if they see a consistent append-only log.  If enough reputable parties run
witnesses that signed-off the same STH, you can be pretty sure that you see the
same log (and thus the same checksums) as everyone else.

Moreover, if you rely on witness cosigning for security, all you need from, say,
a software publisher, is an artifact, a public verification key, a cosigned STH,
and an inclusion proof up to that STH.  To clarify why that is excellent:
client-side verification becomes completely non-interactive!

### Ecosystem robustness
Our long-term aspiration is that clients should _fail-closed_ if a checksum is
not transparency logged.  This requires a _robust log ecosystem_.  As more
parties get involved by operating compatible logs and witnesses, the overall
reliability and availability improves for everyone.  An important factor to
consider is therefore the _minimal common denominator_ to transparency log
checksums.  As far as we can tell the log's leaf entry must at minimum indicate:
1. What public key should the checksum be attributed to.
2. What opaque data does the checksum _refer to_ such that the log entry can be
analyzed by monitors.

Additional metadata needs can be included in the data that the checksum covers,
and the data itself can be stored in a public unauthenticated archive.  Log APIs
and data formats should also follow the principle of minimal common denominator.
We are still in the process of analyzing this further.

### Spam and log poisoning
Trillian personalities usually have an _admission criteria_ that determines who
can include what in the log.  Without an admission criteria, the log is subject
to both spam (large volumes of data) and poisoning (harmful data).

The advantage of a small leaf is that spamming the log to such an extend that it
becomes a significant storage and bandwidth burden becomes harder.  It also
makes the log's policy easier, e.g., a max data limit is not necessary.

Because every leaf is signed it is possible to apply rate limits per namespace.
As a toy example one could require that a namespace is registered before use,
and that the registration component enforces a single namespace per top-level
domain.  To spam the log you would need an excessive number of domain names.

A more subtle advantage of not logging the actual data is that it becomes more
difficult to poison the log with something harmful.  Transparency logs are
really cryptographic, append-only, and tamper-evident data structures: nothing
can be removed or modified until the log shuts down.  Therefore, as few bytes as
possible should be arbitrary in the log's leaf.  A reasonable goal could be to
not take on a larger risk than Certificate Transparency.

##
<a name="footnote-1">1</a>:
The lack of gossip-audit models that prevent and/or detect _split-views_ is
documented quite well with regards to Certificate Transparency.  See, for
example, the work of
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
