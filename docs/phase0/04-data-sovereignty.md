# 04 - Data Sovereignty

Status: ARCHITECTURAL (frozen).

- Persistent application storage (PostgreSQL 16) targets India-hosted infrastructure.
- Server stores: accounts, devices, device certificates, public prekeys, encrypted envelopes,
  delivery acks, media upload sessions, notification state, transparency state. See
  `services/gateway/migrations/0001_init.sql`.
- Server never stores private identity keys, ratchet state, message keys, media keys, recovery private keys.
- Redis is ephemeral only; never holds ratchet roots, chain keys, message keys, identity keys, media keys, recovery keys.

## Boundaries and non-claims
- "Persistent data hosted in India" is not "all packets stay in India": users abroad, APNs/FCM, and
  CDNs/networks in transit are outside that guarantee.
- APNs/FCM are unavoidable OS delivery boundaries, treated as untrusted external transport.
- Legal/regulatory characterization (e.g. data-protection law) is out of scope for this document.
