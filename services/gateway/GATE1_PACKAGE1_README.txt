PRIVATE MESSENGER — GATE 1 / PACKAGE 1
Per-device gateway request authentication

SCOPE
-----
This package connects the existing PM-Device-V1 request proof to the demo
message relay. It adds PostgreSQL-backed device/account validation, atomic
single-use nonce consumption, HTTP middleware, and authenticated send/fetch/ack
operations. It does not freeze the candidate wire protocol or make the demo
message API production-ready.

INSTALLER
---------
Run the supplied PM_GATE1_PACKAGE1_INSTALL.ps1 from Windows PowerShell. It is
pinned to C:\private-messenger, backs up the three existing source files it
replaces, adds the new source/tests/migration, and does not clean, reset, stage,
or commit the Git working tree.

DATABASE
--------
The installer does NOT run migrations. Apply migrations 0001 through 0005 if
they are not already applied, then apply:

  services/gateway/migrations/0006_device_request_nonces.sql

For a disposable PostgreSQL integration-test database, the existing project
uses the database name pm_enrollment_test_20261030. Set
PM_ENROLLMENT_TEST_DATABASE_URL only when deliberately running integration
tests against that dedicated database. The tests verify the connected database
name and skip when the variable is absent. They do not create databases or run
migrations.

VALIDATION
----------
From CMD:

  cd /d C:\private-messenger\services\gateway
  go test -count=1 ./...

PostgreSQL integration tests are skipped unless
PM_ENROLLMENT_TEST_DATABASE_URL is set to the named disposable test database
and migrations 0001 through 0006 are present.

RUNTIME FLAGS
-------------
Per-device request authentication applies to the explicitly demo-only relay:

  GATEWAY_ENABLE_DEMO_MESSAGE_RELAY=1
  GATEWAY_ENABLE_DEVICE_REQUEST_AUTH=1

The normal database and KT key configuration is still required:

  GATEWAY_DATABASE_URL=...
  KT_LOG_PRIVATE_SEED_FILE=...

In per-device mode, GATEWAY_MESSAGE_AUTH_TOKEN is not used. The gateway fails
startup if the request-auth schema is missing. If per-device auth is disabled,
the existing demo shared-bearer path remains available and continues to log a
warning; it is not per-device authentication.

SECURITY NOTES / LIMITATIONS
----------------------------
- Device DSK public keys are loaded from registered server-side state. The
  request cannot choose its own verification key.
- Account status, device status, all relevant epochs, and consistency between
  authorization and device public-key records are checked under row locks.
- Request nonces are consumed under a PostgreSQL uniqueness constraint in the
  same transaction as request verification. Concurrent replays have one winner.
- Authenticated message operations re-check the authenticated device state in
  the same transaction as enqueue/fetch/ack, closing the gap after middleware
  authentication releases its row locks.
- This package protects only /v1/demo/messages. Existing health, KT and public
  device-directory routes are not made private by this change.
- The Android native signing primitive and instrumentation proof have passed,
  but the Android application's real HTTP networking call sites have not yet
  been wired to attach PM-Device-V1 authorization headers.
- Full two-device messaging, anti-rollback assurance, durable Android ratchet
  persistence, production API contract freeze, and independent security review
  remain later gates.
