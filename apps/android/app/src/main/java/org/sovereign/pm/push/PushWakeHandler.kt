package org.sovereign.pm.push

/**
 * Push is a wake-up HINT only. The payload (notification_id, coarse expires_at, opaque
 * 16-byte sync_ticket) has ZERO authorization weight. Flow:
 *   wake-up hint -> authenticated app connection -> message fetch -> ratchet verification -> UI.
 * Never render content or sender info from the push itself.
 */
interface PushWakeHandler {
    fun onWakeHint(notificationId: String)
}
