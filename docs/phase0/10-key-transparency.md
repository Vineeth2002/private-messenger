# 10 - Key Transparency

Status: ARCHITECTURAL (frozen concept); implementation NOT STARTED (sequenced after the handshake, ratchet, media and push boundaries).

Append-only structure: Sparse Merkle Tree, Signed Tree Heads, witnesses, client high-water mark.

| State | Examples | Messaging |
|---|---|---|
| VERIFIED | all checks succeed | allowed |
| DEGRADED | witness timeout, temporary network loss, incomplete quorum with valid cached state | continues |
| SECURITY FAILURE | rollback, stale tree head, inclusion-proof mismatch, conflicting STHs (equivocation), uncommitted identity parameters | outbound messaging to the affected identity BLOCKED |

Transparency leaves are signed structures: unknown cryptographic fields cause parse failure
(PM-CBOR-2026 Rule 7).
