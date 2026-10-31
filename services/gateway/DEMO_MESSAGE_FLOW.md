# Message Relay Live Demo

This bundle provides a demo-only opaque message relay. The gateway does not decrypt message envelopes.

The demo relay is disabled by default. It is not the production per-device messaging API.

## Enable the demo relay explicitly

Set both environment variables:

- `GATEWAY_ENABLE_DEMO_MESSAGE_RELAY=1`
- `GATEWAY_MESSAGE_AUTH_TOKEN` to a randomly generated secret containing at least 32 bytes.

For example, in a local development environment:

```text
GATEWAY_ENABLE_DEMO_MESSAGE_RELAY=1
GATEWAY_MESSAGE_AUTH_TOKEN=<at-least-32-byte-random-secret>
```

When the enable flag is absent or has any value other than `1`, the gateway does not register the demo message relay routes.

When the relay is enabled, an empty or missing bearer-token configuration is rejected at startup. Every demo message route requires:

```text
Authorization: Bearer <the-configured-secret>
```

The shared bearer credential is only a demo transport guard. It does not authenticate an individual device, bind a request to a device's private key, or make caller-supplied device IDs trustworthy. Do not expose this relay as a production messaging endpoint.

## Routes

`POST /v1/demo/messages`

- Body: raw `MessageEnvelopeV1` PM-CBOR-2026 bytes.
- Optional `X-Message-Expires-At: <RFC3339Nano>`.
- If omitted, the demo assigns a 15-minute expiry. This is demo policy only and is not a frozen production contract.

`GET /v1/demo/messages/{recipient_device_id}`

- Returns JSON with base64-encoded opaque envelopes.
- Expired envelopes are opportunistically deleted.
- `?limit=` supports 1..100.

`POST /v1/demo/messages/{recipient_device_id}/{envelope_id}/ack`

- Records a delivery acknowledgement.
- Acks are idempotent while the envelope is valid.

## Live polling flow

1. Start the gateway with `GATEWAY_DATABASE_URL` and the existing `KT_LOG_PRIVATE_SEED_FILE`.
2. Explicitly enable the demo relay and configure a sufficiently long `GATEWAY_MESSAGE_AUTH_TOKEN`.
3. POST an actual `MessageEnvelopeV1` from Device A with the bearer token.
4. Poll GET for Device B's ID with the bearer token.
5. Base64-decode the returned `envelope_cbor_base64` and feed the bytes to the client ratchet/crypto layer.
6. POST the returned `envelope_id` to the ACK route with the bearer token.

The server only stores/routes the opaque envelope. This demo flow does not provide authenticated per-device sessions and is not production-ready.
