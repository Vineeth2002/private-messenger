# 09 - Notifications (HPKE Base push)

Status: ARCHITECTURAL (frozen); implementation NOT STARTED (sequenced after the handshake, ratchet and media boundaries).

Push is a wake-up hint only (APNs/FCM). The payload MUST NOT contain sender handle/user ID, avatar,
conversation ID, message ID, preview, plaintext, or file metadata. Contents: `notification_id`
(UUIDv7), coarse `expires_at`, opaque 16-byte `sync_ticket`.

Encryption: stateless HPKE Base mode (RFC 9180): confidentiality, NOT sender authentication, so push
is never authoritative. The `sync_ticket` has zero authorization weight.

Flow: wake-up hint -> authenticated application connection -> message fetch -> ratchet
verification -> UI presentation.

Non-claims: platform metadata (token, IP, packet size, timing) is unavoidable and outside the
application-metadata guarantee; APNs/FCM are untrusted external boundaries.
