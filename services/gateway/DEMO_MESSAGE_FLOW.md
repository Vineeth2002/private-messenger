# Message Relay Live Demo

This bundle adds a demo-only end-to-end opaque message relay. The gateway does not decrypt the envelope.

## Routes

POST `/v1/demo/messages`
- Body: raw `MessageEnvelopeV1` PM-CBOR-2026 bytes.
- Optional `X-Message-Expires-At: <RFC3339Nano>`.
- If omitted, the demo assigns a 15-minute expiry. This is demo policy only and is not a frozen production contract.

GET `/v1/demo/messages/{recipient_device_id}`
- Returns JSON with base64-encoded opaque envelopes.
- Expired envelopes are opportunistically deleted.
- `?limit=` supports 1..100.

POST `/v1/demo/messages/{recipient_device_id}/{envelope_id}/ack`
- Records a delivery acknowledgement.
- Acks are idempotent while the envelope is valid.

## Optional demo bearer guard

Set:

`GATEWAY_MESSAGE_AUTH_TOKEN=change-me`

Clients must then send:

`Authorization: Bearer change-me`

This is a demo transport guard, not the final per-device authenticated-session protocol.

## Live polling flow

1. Start the gateway with `GATEWAY_DATABASE_URL` and the existing `KT_LOG_PRIVATE_SEED_FILE`.
2. POST an actual `MessageEnvelopeV1` from Device A.
3. Poll GET for Device B's ID.
4. Base64-decode the returned `envelope_cbor_base64` and feed the bytes to the client ratchet/crypto layer.
5. POST the returned `envelope_id` to the ACK route.

The server only stores/routes the opaque envelope.
