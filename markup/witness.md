# Witness cosigning
Transparency logs were designed to be cryptographically verifiable in the
presence of a gossip-audit model that ensures everyone observes _the same
cryptographically verifiable log_.  The gossip-audit model is largely undefined
in today's existing transparency logging ecosystems, which means that the logs
must be trusted to play by the rules.   We wanted to avoid that outcome in our
ecosystem.  Therefore, a gossip-audit model is built into the log.

The basic idea is that an STH should only be considered valid if it is cosigned
by a number of witnesses that verify the append-only property.  Which witnesses
to trust and under what circumstances is defined by a client-side _witness
cosigning policy_.  For example,
	"require no witness cosigning",
	"must have at least `k` signatures from witnesses A...J", and
	"must have at least `k` signatures from witnesses A...J where one is from
		witness B".

Witness cosigning policies are beyond the scope of this specification.

The log is configured with a list of witness namespaces. The only supported
witness namespace format is `ed25519_v1`.  The signature must span a serialized
`signed_tree_head_v1` item.

## Public endpoints
Witnesses are expected to poll the `next-cosi` endpoint.  If a new STH is
obtained:
1. Verify that the log is append-only by fetching a consistency proof from the
latest STH that this witness co-signed.  Stop if no valid proof is available.
2. Sign the STH and submit using the `add-cosi` API.

### add-cosi
```
POST https://<base url>/st/v1/add-cosi
```

Input:
- sth: an `StItem` of type `signed_tree_head_v1`.
- namespace: a `Namespace` item of type `ed25519_v1`.
- signature: covers the specified STH.

Output:
- None

### get-cosi
```
GET https://<base url>/st/v1/get-cosi
```

Input:
- None

Output:
- A map with keys "sth" and "signatures".  The former is an `StItem` of type
`signed_tree_head_v1`.  The latter an array where each entry is a map with a
"witness" (`ed25519_v1` namespace) and a "signature".

### next-cosi
```
GET https://<base url>/st/v1/next-cosi
```

Input
- None

Output:
- an `StItem` of type `signed_tree_head_v1`, which corresponds to the STH
that is currently being cosigned. Stable for a period of time, e.g., 10 minutes.
