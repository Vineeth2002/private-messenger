# Recovery API deployment requirements

The recovery API remains disabled unless `GATEWAY_ENABLE_RECOVERY_API=1` is set.

## Shared rate limiting

The recovery API uses PostgreSQL-backed fixed-window rate limiting: 10 requests
per peer per 60-second database-time window. IPv4 peers are tracked as `/32`;
IPv6 peers are grouped by `/64` to reduce simple address-rotation bypasses. The
database stores only an HMAC-SHA-256 digest of the normalized peer identity,
not the raw IP address.

Before enabling the API, apply migration
`migrations/0009_recovery_api_rate_limits.sql` to the gateway database.

Set `GATEWAY_RECOVERY_RATE_LIMIT_HMAC_KEY` to exactly 64 hexadecimal
characters representing 32 cryptographically random bytes. Generate a key
once, store it in the deployment secret manager, and provide the identical
value to every gateway instance using the same database. Do not commit it to
the repository. Rotating the key resets existing rate-limit identities and
therefore temporarily resets their counters.

The limiter fails closed: if PostgreSQL cannot consume the quota, the recovery
endpoint returns `503 ERR_RATE_LIMIT_UNAVAILABLE` rather than proceeding without
rate limiting. Expired counter rows are pruned at startup and hourly.

## Client IP and reverse proxies

The gateway currently derives peer identity from the TCP `RemoteAddr` only. It
does not trust `Forwarded`, `X-Forwarded-For`, or similar client-controlled
headers. This is correct for direct connections. If a reverse proxy is placed
in front of the gateway, every client may appear as the proxy and share one
quota. Do not fix that by blindly accepting forwarded headers. Add an explicit
trusted-proxy CIDR configuration and validate the forwarding chain before
using a forwarded client address.

## Transport and network boundary

The gateway's `ListenAndServe` listener is plain HTTP. HTTPS must be terminated
by a trusted ingress/reverse proxy or another protected transport boundary.
Block direct public access to the gateway listener when an ingress is used.
The PostgreSQL rate limiter is not a substitute for TLS, network firewalls,
volumetric DDoS protection, or ingress-wide request limits.

Keep `GATEWAY_ENABLE_RECOVERY_API` unset until TLS termination, network access
controls, migration 0009, and the shared HMAC secret have been verified in the
target deployment.
