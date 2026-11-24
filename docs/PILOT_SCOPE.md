# 14-Day Controlled B2B Pilot Scope (India-Hosted 1:1 Alpha)

**Target Pilot Segment:** Indian Chartered Accountant (CA) & boutique legal practices (5–15 seats)  
**Pilot Pricing:** ₹299/seat/month (14-day closed pilot with ₹500 refundable UPI slot)  
**Disclaimer:** Controlled Android 1:1 alpha. **Not** independently audited; **not** for regulated client/production data until P9 assurance is complete.

---

## 1. Included in the 14-Day Pilot (Frozen Scope)

1. **Gateway Delivery (`services/gateway/`):**
   - Idempotent `Enqueue` / `EnqueueAuthenticated` (`ON CONFLICT (envelope_id) DO NOTHING`, `deduplicated` flag, `409 ERR_ENVELOPE_CONFLICT` on payload/recipient mismatch).
   - Idempotent `ACK` (`delivery_acks`) and 15-minute message TTL.
2. **Android 1:1 Client (`apps/android/`):**
   - Outbox retry & reconciliation (`DELIVERY_UNKNOWN` and post-kill `ATTEMPTING` recovery).
   - `WorkManager` background sync (`BackgroundSyncScheduler` 15-minute periodic + `WorkManagerPushWakeHandler` wake-hint coalescing) with metadata-free local notifications.
   - Unified light/dark `SovereignTheme` (`SovereignSlatePalette` backed by `MaterialTheme.colorScheme`) and `alphaOnlyMode = true` hiding unbacked P7–P8 tabs/menus.
   - Manual out-of-band peer fingerprint comparison.

## 2. Explicitly Frozen (Out of Scope for Pilot)

- **UI / Features:** Updates, Status, Channels, Communities, Voice/Video Calls, Linked Devices, Group chats, Encrypted media (P6–P8).
- **Platforms:** iOS app (no Xcode project until Android 1:1 pilot retention is proven).
- **Assurance (P9):** Key Transparency witness model and independent cryptographic audit (funded after 50+ paid seats are committed).

## 3. Two-Device Acceptance Gate (Pass Criteria)

1. Two physical Android devices pair via manual fingerprint verification.
2. Send, reply, and ACK succeed across foreground and background (`WorkManager`).
3. Simulated network drop during `POST /v1/demo/messages` reconciles via `DELIVERY_UNKNOWN` retry with zero duplicate messages on the recipient device.
4. App kill mid-send recovers cleanly on restart.
5. Both devices exchange messages reliably for **7 consecutive days**.

## 4. Push & Verify via `cmd` (Windows)

```cmd
cd services\gateway
go test ./...
go vet ./...
cd ..\..\apps\android
gradlew.bat :app:compileDebugKotlin testDebugUnitTest
cd ..\..
git add docs\PILOT_SCOPE.md services\gateway\ apps\android\
git commit -m "pilot: freeze 14-day B2B alpha scope, idempotent delivery, and background sync"
git push
```
