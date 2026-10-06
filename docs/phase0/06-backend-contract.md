# 06 - Backend Contract

Status: ARCHITECTURAL (frozen responsibilities); HTTP/API shapes NOT yet specified.

The backend is a delivery/control plane. Responsibilities: authentication/session management;
device directory; public-key and prekey distribution; encrypted-envelope routing; delivery
acknowledgement; expiration; rate limiting; push signaling; media-upload control plane;
transparency publication. It never decrypts E2EE content.

Phase A surface (`services/gateway`): `GET /healthz`; `POST /v1/cbor/validate` (204 if the body is
valid PM-CBOR-2026, else 400 `{"error":"ERR_..."}`). All structured bodies are PM-CBOR-2026 and are
proven canonical from the original bytes before use.
