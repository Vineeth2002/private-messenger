#!/usr/bin/env python3
"""
Automated acceptance & idempotency verification harness for
Sovereign Private Messenger (Section 6, Steps 4-5 of ROADMAP_P0_P9_CANONICAL_2026-11-19.md).

Verifies:
1. 1:1 send -> fetch -> idempotent ACK
2. Ambiguous send retry (same envelope_id + same recipient + same CBOR) -> deduplicated 202
3. Conflicting envelope_id replay (different payload or recipient) -> 409 ERR_ENVELOPE_CONFLICT
4. Expired envelope exclusion on fetch & ACK
"""

import sqlite3
import unittest
import uuid
from datetime import datetime, timedelta, timezone


class GatewayDeliverySimulator:
    """In-memory SQLite model matching services/gateway/internal/messages/delivery.go."""

    def __init__(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute(
            """
            CREATE TABLE message_envelopes (
                envelope_id TEXT PRIMARY KEY,
                recipient_device TEXT NOT NULL,
                envelope_cbor BLOB NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE delivery_acks (
                envelope_id TEXT PRIMARY KEY,
                acked_at TEXT NOT NULL
            )
            """
        )

    def enqueue(
        self,
        envelope_id: str,
        recipient_device: str,
        envelope_cbor: bytes,
        now: datetime,
        expires_at: datetime,
    ) -> tuple[int, dict]:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT OR IGNORE INTO message_envelopes (
                envelope_id, recipient_device, envelope_cbor, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                envelope_id,
                recipient_device,
                envelope_cbor,
                now.isoformat(),
                expires_at.isoformat(),
            ),
        )
        if cur.rowcount == 1:
            self.conn.commit()
            return 202, {
                "envelope_id": envelope_id,
                "recipient_device_id": recipient_device,
                "created_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "deduplicated": False,
            }

        row = cur.execute(
            """
            SELECT recipient_device, envelope_cbor, created_at, expires_at
            FROM message_envelopes
            WHERE envelope_id = ?
            """,
            (envelope_id,),
        ).fetchone()
        if row is None:
            return 500, {"error": "ERR_MESSAGE_DELIVERY"}

        existing_recipient, existing_cbor, created_at, persisted_expires_at = row
        if existing_recipient != recipient_device or existing_cbor != envelope_cbor:
            return 409, {"error": "ERR_ENVELOPE_CONFLICT"}

        return 202, {
            "envelope_id": envelope_id,
            "recipient_device_id": existing_recipient,
            "created_at": created_at,
            "expires_at": persisted_expires_at,
            "deduplicated": True,
        }

    def fetch(self, recipient_device: str, now: datetime) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT m.envelope_id, m.envelope_cbor, m.created_at, m.expires_at
            FROM message_envelopes m
            LEFT JOIN delivery_acks a ON a.envelope_id = m.envelope_id
            WHERE m.recipient_device = ?
              AND a.envelope_id IS NULL
              AND m.expires_at > ?
            ORDER BY m.created_at ASC
            """,
            (recipient_device, now.isoformat()),
        ).fetchall()
        return [
            {
                "envelope_id": r[0],
                "envelope_cbor": r[1],
                "created_at": r[2],
                "expires_at": r[3],
            }
            for r in rows
        ]

    def ack(self, envelope_id: str, recipient_device: str, now: datetime) -> int:
        row = self.conn.execute(
            """
            SELECT expires_at
            FROM message_envelopes
            WHERE envelope_id = ? AND recipient_device = ?
            """,
            (envelope_id, recipient_device),
        ).fetchone()
        if row is None or row[0] <= now.isoformat():
            return 404

        self.conn.execute(
            """
            INSERT OR IGNORE INTO delivery_acks (envelope_id, acked_at)
            VALUES (?, ?)
            """,
            (envelope_id, now.isoformat()),
        )
        self.conn.commit()
        return 204


class TestGatewayIdempotencyAndAcceptance(unittest.TestCase):
    def setUp(self) -> None:
        self.gw = GatewayDeliverySimulator()
        self.t0 = datetime(2026, 11, 24, 11, 0, 0, tzinfo=timezone.utc)
        self.expires = self.t0 + timedelta(minutes=15)
        self.device_b = str(uuid.uuid4())
        self.device_c = str(uuid.uuid4())

    def test_ambiguous_send_retry_is_idempotent(self) -> None:
        env_id = str(uuid.uuid4())
        payload = b"\xa1\x63msg\x65hello"

        status1, body1 = self.gw.enqueue(env_id, self.device_b, payload, self.t0, self.expires)
        self.assertEqual(status1, 202)
        self.assertFalse(body1["deduplicated"])

        # Client retries 5s later after dropped HTTP response
        t_retry = self.t0 + timedelta(seconds=5)
        status2, body2 = self.gw.enqueue(
            env_id, self.device_b, payload, t_retry, t_retry + timedelta(minutes=15)
        )
        self.assertEqual(status2, 202)
        self.assertTrue(body2["deduplicated"])
        self.assertEqual(body2["created_at"], body1["created_at"])
        self.assertEqual(body2["expires_at"], body1["expires_at"])

        # Recipient only receives 1 copy
        inbox = self.gw.fetch(self.device_b, t_retry)
        self.assertEqual(len(inbox), 1)
        self.assertEqual(inbox[0]["envelope_id"], env_id)

    def test_conflicting_envelope_id_returns_409(self) -> None:
        env_id = str(uuid.uuid4())
        status1, _ = self.gw.enqueue(env_id, self.device_b, b"cbor-v1", self.t0, self.expires)
        self.assertEqual(status1, 202)

        # Same envelope_id, different payload
        status2, body2 = self.gw.enqueue(env_id, self.device_b, b"cbor-v2", self.t0, self.expires)
        self.assertEqual(status2, 409)
        self.assertEqual(body2["error"], "ERR_ENVELOPE_CONFLICT")

        # Same envelope_id, different recipient
        status3, body3 = self.gw.enqueue(env_id, self.device_c, b"cbor-v1", self.t0, self.expires)
        self.assertEqual(status3, 409)
        self.assertEqual(body3["error"], "ERR_ENVELOPE_CONFLICT")

    def test_idempotent_ack_and_expiry(self) -> None:
        env_id = str(uuid.uuid4())
        self.gw.enqueue(env_id, self.device_b, b"cbor-msg", self.t0, self.expires)

        self.assertEqual(self.gw.ack(env_id, self.device_b, self.t0 + timedelta(seconds=10)), 204)
        self.assertEqual(self.gw.ack(env_id, self.device_b, self.t0 + timedelta(seconds=20)), 204)
        self.assertEqual(self.gw.fetch(self.device_b, self.t0 + timedelta(seconds=25)), [])

        # Expired envelope cannot be fetched or acked
        env_exp = str(uuid.uuid4())
        self.gw.enqueue(env_exp, self.device_b, b"cbor-exp", self.t0, self.expires)
        after_expiry = self.expires + timedelta(seconds=1)
        self.assertEqual(self.gw.fetch(self.device_b, after_expiry), [])
        self.assertEqual(self.gw.ack(env_exp, self.device_b, after_expiry), 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
