import UserNotifications

/// Notification Service Extension boundary.
/// The push payload is a wake-up hint only (notification_id, coarse expires_at, opaque sync_ticket)
/// and carries ZERO authorization weight. The extension must NOT display content derived from
/// the push; any message content requires an authenticated fetch + ratchet verification first.
final class NotificationService: UNNotificationServiceExtension {
    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        let content = (request.content.mutableCopy() as? UNMutableNotificationContent) ?? UNMutableNotificationContent()
        content.title = "New message"   // static placeholder; no sender, preview, or conversation info
        content.body = ""
        contentHandler(content)
    }
}
