# 01 - Product Specification (V1 scope)

Status: ARCHITECTURAL (frozen). Source: bootstrap handoff, sections 1-4, 44.

## Thesis
A global private messenger engineered in India: persistent application data hosted in India,
strong E2EE, client-owned cryptographic state, privacy-preserving infrastructure. Usable globally
(India <-> USA/UK/France/UAE/Australia ...). Not an "Indian WhatsApp".

## V1 features (secure 1-to-1)
Text; encrypted photos, videos, documents, voice notes; 1-to-1 voice and video calls; call
history; missed-call handling; missed-call -> private voice-message fallback; reply; reactions;
edit; delete; delivery and read state; disappearing messages; search; multi-device foundation.

- Missed-call fallback: after a missed call the app may offer "Leave a private voice message?".
  The recording is encrypted and delivered as a secure voice message tied to call history.
- Call recording is a local-client feature only, with explicit participant-visible indication and
  consent. Never silent.

## Identity / discovery (V1)
Username, direct QR verification, signed invite links. Phone-number discovery is optional/future.
VOPRF private contact discovery is deferred (do not implement).

## Future (not blockers for the cryptographic foundation)
Language Lens, Learning Mode, on-device AI: see 05-ai-privacy.md.

## Stages
0 Architecture/threat model (done) - A Repo scaffolding, strict serialization, shared vectors
(done: gate met 2026-10-05) - B Production crypto + security validation (next: unlocked, not started,
one boundary at a time) - 1 Android MVP - 2 iOS + calling/notifications - 3 Groups + multi-device -
4 Language Lens + on-device AI - 5 Advanced/future.
