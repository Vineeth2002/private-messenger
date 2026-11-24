#!/usr/bin/env python3
"""
Two-device outbox reconciliation & acceptance test harness
matching PersistentMessagingEngine.kt + LocalMessagingDatabase.kt + delivery.go.

Simulates:
1. Normal 1:1 send -> fetch -> ACK
2. App kill mid-send (ATTEMPTING) -> restart recovery -> idempotent retry -> SUBMITTED
3. Network timeout (DELIVERY_UNKNOWN) -> reconnect retry -> 202 deduplicated=true -> SUBMITTED
4. Permanent 409 ERR_ENVELOPE_CONFLICT -> stops retrying without corrupting outbox
"""

import unittest
import uuid
from datetime import datetime, timedelta, timezone

from test_idempotency_and_acceptance import GatewayDeliverySimulator


class AndroidOutboxClientSimulator:
    def __init__(self, device_id: str, gateway: GatewayDeliverySimulator) -> None:
        self.device_id = device_id
        self.gateway = gateway
        # local_message_id -> dict
        self.outbox: dict[str, dict] = {}
        self.inbox_acked: set[str] = set()

    def queue_message(self, local_id: str, envelope_id: str, recipient: str, payload: bytes) -> None:
        self.outbox[local_id] = {
            "local_message_id": local_id,
            "gateway_envelope_id": envelope_id,
            "recipient_device": recipient,
            "envelope_wire": payload,
            "state": "READY",
            "attempt_count": 0,
            "last_error_code": None,
        }

    def simulate_app_kill_during_attempt(self, local_id: str) -> None:
        item = self.outbox[local_id]
        item["state"] = "ATTEMPTING"
        item["attempt_count"] += 1

    def recover_and_reconcile(
        self,
        now: datetime,
        drop_response_once: bool = False,
        max_attempts: int = 5,
    ) -> list[str]:
        """Mirrors recoverStaleAttemptingOutbox + reconcileAmbiguousOutbox."""
        submitted: list[str] = []
        # 1. Recover any ATTEMPTING rows left over from an app kill
        for item in self.outbox.values():
            if item["state"] == "ATTEMPTING":
                item["state"] = "DELIVERY_UNKNOWN"

        # 2. Process READY and retryable DELIVERY_UNKNOWN rows
        for item in self.outbox.values():
            if item["state"] not in ("READY", "DELIVERY_UNKNOWN"):
                continue
            if item["attempt_count"] >= max_attempts:
                continue

            item["state"] = "ATTEMPTING"
            item["attempt_count"] += 1

            status, body = self.gateway.enqueue(
                item["gateway_envelope_id"],
                item["recipient_device"],
                item["envelope_wire"],
                now,
                now + timedelta(minutes=15),
            )
            if drop_response_once:
                # Server persisted it, but client timed out before reading 202
                item["state"] = "DELIVERY_UNKNOWN"
                item["last_error_code"] = "NETWORK_TIMEOUT"
                drop_response_once = False
                continue

            if status == 202:
                item["state"] = "SUBMITTED"
                item["last_error_code"] = None
                submitted.append(item["local_message_id"])
            elif status in (400, 403, 404, 409):
                item["state"] = "FAILED_PERMANENT"
                item["last_error_code"] = body.get("error", f"HTTP_{status}")
            else:
                item["state"] = "DELIVERY_UNKNOWN"
                item["last_error_code"] = body.get("error", f"HTTP_{status}")

        return submitted


class TestTwoDeviceOutboxAcceptance(unittest.TestCase):
    def setUp(self) -> None:
        self.gw = GatewayDeliverySimulator()
        self.t0 = datetime(2026, 11, 24, 11, 20, 0, tzinfo=timezone.utc)
        self.alice_dev = str(uuid.uuid4())
        self.bob_dev = str(uuid.uuid4())
        self.alice = AndroidOutboxClientSimulator(self.alice_dev, self.gw)

    def test_dropped_response_then_reconnect_reconciles_without_duplicate(self) -> None:
        env_id = str(uuid.uuid4())
        self.alice.queue_message("msg-1", env_id, self.bob_dev, b"cbor-hello-bob")

        # First attempt: server persists envelope, but HTTP response is dropped
        submitted_1 = self.alice.recover_and_reconcile(self.t0, drop_response_once=True)
        self.assertEqual(submitted_1, [])
        self.assertEqual(self.alice.outbox["msg-1"]["state"], "DELIVERY_UNKNOWN")
        self.assertEqual(self.alice.outbox["msg-1"]["attempt_count"], 1)

        # Reconnect 5s later: client retries same envelope_id, gateway deduplicates
        t_reconnect = self.t0 + timedelta(seconds=5)
        submitted_2 = self.alice.recover_and_reconcile(t_reconnect)
        self.assertEqual(submitted_2, ["msg-1"])
        self.assertEqual(self.alice.outbox["msg-1"]["state"], "SUBMITTED")
        self.assertEqual(self.alice.outbox["msg-1"]["attempt_count"], 2)

        # Bob fetches and sees exactly 1 message, then ACKs
        bob_inbox = self.gw.fetch(self.bob_dev, t_reconnect)
        self.assertEqual(len(bob_inbox), 1)
        self.assertEqual(self.gw.ack(env_id, self.bob_dev, t_reconnect), 204)
        self.assertEqual(self.gw.fetch(self.bob_dev, t_reconnect), [])

    def test_app_kill_mid_attempt_recovers_on_restart(self) -> None:
        env_id = str(uuid.uuid4())
        self.alice.queue_message("msg-kill", env_id, self.bob_dev, b"cbor-restart")
        self.alice.simulate_app_kill_during_attempt("msg-kill")
        self.assertEqual(self.alice.outbox["msg-kill"]["state"], "ATTEMPTING")

        submitted = self.alice.recover_and_reconcile(self.t0 + timedelta(seconds=10))
        self.assertEqual(submitted, ["msg-kill"])
        self.assertEqual(self.alice.outbox["msg-kill"]["state"], "SUBMITTED")

    def test_409_conflict_stops_retrying(self) -> None:
        env_id = str(uuid.uuid4())
        # Pre-seed gateway with a different payload for the same envelope_id
        self.gw.enqueue(env_id, self.bob_dev, b"cbor-original", self.t0, self.t0 + timedelta(minutes=15))

        self.alice.queue_message("msg-conflict", env_id, self.bob_dev, b"cbor-tampered")
        submitted = self.alice.recover_and_reconcile(self.t0 + timedelta(seconds=2))
        self.assertEqual(submitted, [])
        self.assertEqual(self.alice.outbox["msg-conflict"]["state"], "FAILED_PERMANENT")
        self.assertEqual(self.alice.outbox["msg-conflict"]["last_error_code"], "ERR_ENVELOPE_CONFLICT")


if __name__ == "__main__":
    unittest.main(verbosity=2)
