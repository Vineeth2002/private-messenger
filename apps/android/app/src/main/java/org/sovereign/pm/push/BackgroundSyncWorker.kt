package org.sovereign.pm.push

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import org.sovereign.pm.messaging.LocalMessagingDatabase

class BackgroundSyncWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val db = LocalMessagingDatabase(applicationContext)
        return try {
            // Wire your initialized DeviceMessageHttpClient + PersistentMessagingEngine here:
            // 1. engine.reconcileAmbiguousOutbox(client)
            // 2. val newlyReceived = engine.processIncomingMessages(client, peerTrust)
            // 3. if (newlyReceived > 0) showPrivacyPreservingNotification(newlyReceived)
            val newlyReceived = 0
            if (newlyReceived > 0) {
                showPrivacyPreservingNotification(newlyReceived)
            }
            Result.success()
        } catch (e: Exception) {
            if (runAttemptCount < MAX_RETRY_ATTEMPTS) Result.retry() else Result.failure()
        } finally {
            db.close()
        }
    }

    private fun showPrivacyPreservingNotification(count: Int) {
        val manager = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Encrypted Messages",
                NotificationManager.IMPORTANCE_DEFAULT,
            )
            manager.createNotificationChannel(channel)
        }
        val body = if (count > 1) "You have new encrypted messages" else "You have a new encrypted message"
        val notification = NotificationCompat.Builder(applicationContext, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentTitle("Sovereign Private Messenger")
            .setContentText(body)
            .setAutoCancel(true)
            .build()
        manager.notify(NOTIFICATION_ID, notification)
    }

    companion object {
        const val KEY_NOTIFICATION_ID = "notification_id"
        private const val CHANNEL_ID = "sovereign_pm_messages"
        private const val NOTIFICATION_ID = 1001
        private const val MAX_RETRY_ATTEMPTS = 5
    }
}
