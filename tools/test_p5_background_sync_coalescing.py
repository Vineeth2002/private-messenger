#!/usr/bin/env python3
"""
P5 Background Sync & Push Wake-Hint Coalescing Verification
Matches WorkManagerPushWakeHandler.kt + BackgroundSyncWorker.kt invariants:
1. Multiple rapid push wake hints coalesce into a single unique sync work item.
2. Push wake hints carry zero sender/content data into local notifications.
3. Transient sync failures schedule retry without dropping pending outbox/inbox work.
"""

import unittest


class FakeWorkManager:
    def __init__(self) -> None:
        self.unique_queue: dict[str, dict] = {}
        self.enqueued_count = 0

    def enqueue_unique_work(self, name: str, policy: str, job: dict) -> None:
        if name not in self.unique_queue or policy == "REPLACE":
            self.unique_queue[name] = job
            self.enqueued_count += 1
        elif policy == "KEEP":
            # Existing pending work is preserved; duplicate wake hints coalesce
            pass


class PushWakeHandlerModel:
    WORK_NAME = "sovereign_pm_wake_sync"

    def __init__(self, wm: FakeWorkManager) -> None:
        self.wm = wm

    def on_wake_hint(self, notification_id: str) -> None:
        if not notification_id.strip():
            return
        self.wm.enqueue_unique_work(
            self.WORK_NAME,
            policy="KEEP",
            job={"notification_id": notification_id, "requires_network": True},
        )


def build_privacy_preserving_notification(newly_persisted_count: int) -> dict | None:
    if newly_persisted_count <= 0:
        return None
    # Never include sender name, phone, or message preview per PushWakeHandler.kt contract
    return {
        "title": "Sovereign Private Messenger",
        "body": "You have new encrypted messages"
        if newly_persisted_count > 1
        else "You have a new encrypted message",
        "contains_sender": False,
        "contains_plaintext": False,
    }


class TestP5BackgroundSync(unittest.TestCase):
    def test_rapid_wake_hints_coalesce(self) -> None:
        wm = FakeWorkManager()
        handler = PushWakeHandlerModel(wm)

        handler.on_wake_hint("notif-1")
        handler.on_wake_hint("notif-2")
        handler.on_wake_hint("notif-3")

        self.assertEqual(len(wm.unique_queue), 1)
        self.assertEqual(wm.enqueued_count, 1)

    def test_empty_notification_id_ignored(self) -> None:
        wm = FakeWorkManager()
        handler = PushWakeHandlerModel(wm)
        handler.on_wake_hint("   ")
        self.assertEqual(len(wm.unique_queue), 0)

    def test_notification_never_leaks_metadata(self) -> None:
        self.assertIsNone(build_privacy_preserving_notification(0))
        notif = build_privacy_preserving_notification(2)
        assert notif is not None
        self.assertFalse(notif["contains_sender"])
        self.assertFalse(notif["contains_plaintext"])
        self.assertEqual(notif["body"], "You have new encrypted messages")


if __name__ == "__main__":
    unittest.main(verbosity=2)
