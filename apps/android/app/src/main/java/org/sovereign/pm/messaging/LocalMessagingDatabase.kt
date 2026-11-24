package org.sovereign.pm.messaging

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.util.UUID

internal enum class StoredMessageDirection { OUTBOUND, INBOUND }

internal enum class OutboxState { READY, ATTEMPTING, SUBMITTED, DELIVERY_UNKNOWN }

internal data class StoredMessagingSession(
    val sessionId: ByteArray,
    val peerAccountId: ByteArray,
    val peerDeviceId: ByteArray,
    val localEpoch: Long,
    val peerEpoch: Long,
    val generation: Long,
    val encryptedSnapshot: ByteArray,
    val firstPrekeyHeader: ByteArray,
    val createdAtMillis: Long,
    val updatedAtMillis: Long,
)

internal data class StoredSignedPrekey(
    val accountEpoch: Long,
    val signedPrekeyId: Long,
    val rawSignedPrekey: ByteArray,
    val encryptedPrivateRecord: ByteArray,
    val createdAtMillis: Long,
)

/**
 * A database message draft accepts only encrypted local content and the already-encrypted
 * MessageEnvelopeV1 wire object. Plaintext is deliberately not part of this persistence API.
 */
internal data class EncryptedMessageDraft(
    val localMessageId: String,
    val sessionId: ByteArray,
    val protocolEnvelopeId: ByteArray,
    val direction: StoredMessageDirection,
    val generation: Long,
    val encryptedBody: ByteArray,
    val envelopeWire: ByteArray,
    val createdAtMillis: Long,
)

internal data class StoredMessage(
    val localMessageId: String,
    val sessionId: ByteArray,
    val protocolEnvelopeId: ByteArray,
    val direction: StoredMessageDirection,
    val generation: Long,
    val encryptedBody: ByteArray,
    val envelopeWire: ByteArray,
    val createdAtMillis: Long,
)

internal data class ReadyOutboxMessage(
    val localMessageId: String,
    val envelopeWire: ByteArray,
    val attemptCount: Long,
)

internal data class StoredOutboxStatus(
    val state: OutboxState,
    val attemptCount: Long,
    val gatewayEnvelopeId: String?,
    val lastErrorCode: String?,
)

internal enum class IncomingCommitResult { INSERTED, DUPLICATE }

internal class StaleSessionGenerationException(message: String) : IllegalStateException(message)

/**
 * SQLite metadata store for E2EE messaging.
 *
 * Sensitive values are stored only as opaque encrypted blobs:
 * - ratchet snapshots are produced by native seal_ratchet_state/storage-record code;
 * - message bodies are produced by MessagingSession.sealLocalMessageBody;
 * - signed-prekey private records are produced by SignedPrekeyContext.sealForStorage;
 * - envelopeWire contains the native E2EE MessageEnvelopeV1 ciphertext.
 *
 * IDs, peer/device identifiers, timestamps, delivery state and routing metadata remain visible
 * in SQLite. This is application-level payload encryption, not full-database encryption.
 */
internal class LocalMessagingDatabase(
    context: Context,
    databaseName: String = DATABASE_NAME,
) : SQLiteOpenHelper(context.applicationContext, databaseName, null, DATABASE_VERSION) {

    override fun onConfigure(db: SQLiteDatabase) {
        super.onConfigure(db)
        db.setForeignKeyConstraintsEnabled(true)
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE messaging_sessions (
                session_id BLOB NOT NULL PRIMARY KEY CHECK(length(session_id) = 16),
                peer_account_id BLOB NOT NULL CHECK(length(peer_account_id) = 16),
                peer_device_id BLOB NOT NULL CHECK(length(peer_device_id) = 16),
                local_epoch INTEGER NOT NULL CHECK(local_epoch BETWEEN 1 AND 4294967295),
                peer_epoch INTEGER NOT NULL CHECK(peer_epoch BETWEEN 1 AND 4294967295),
                generation INTEGER NOT NULL CHECK(generation >= 0),
                encrypted_snapshot BLOB NOT NULL CHECK(length(encrypted_snapshot) > 0),
                first_prekey_header BLOB NOT NULL,
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms > 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms > 0)
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE signed_prekeys (
                account_epoch INTEGER NOT NULL CHECK(account_epoch BETWEEN 1 AND 4294967295),
                signed_prekey_id INTEGER NOT NULL CHECK(signed_prekey_id BETWEEN 1 AND 4294967295),
                raw_signed_prekey BLOB NOT NULL CHECK(length(raw_signed_prekey) > 0),
                encrypted_private_record BLOB NOT NULL CHECK(length(encrypted_private_record) > 0),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms > 0),
                PRIMARY KEY(account_epoch, signed_prekey_id)
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE messages (
                local_message_id TEXT NOT NULL PRIMARY KEY,
                session_id BLOB NOT NULL REFERENCES messaging_sessions(session_id) ON DELETE RESTRICT,
                protocol_envelope_id BLOB NOT NULL CHECK(length(protocol_envelope_id) = 16),
                direction TEXT NOT NULL CHECK(direction IN ('OUTBOUND', 'INBOUND')),
                generation INTEGER NOT NULL CHECK(generation > 0),
                encrypted_body BLOB NOT NULL CHECK(length(encrypted_body) > 0),
                envelope_wire BLOB NOT NULL CHECK(length(envelope_wire) BETWEEN 1 AND 65552),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms > 0),
                UNIQUE(session_id, protocol_envelope_id)
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE outbox (
                local_message_id TEXT NOT NULL PRIMARY KEY REFERENCES messages(local_message_id) ON DELETE RESTRICT,
                state TEXT NOT NULL CHECK(state IN ('READY', 'ATTEMPTING', 'SUBMITTED', 'DELIVERY_UNKNOWN')),
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                attempt_started_at_ms INTEGER,
                gateway_envelope_id TEXT UNIQUE,
                last_error_code TEXT,
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms > 0)
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE inbox_receipts (
                gateway_envelope_id TEXT NOT NULL PRIMARY KEY,
                local_message_id TEXT NOT NULL UNIQUE REFERENCES messages(local_message_id) ON DELETE RESTRICT,
                ack_state TEXT NOT NULL CHECK(ack_state IN ('ACK_PENDING', 'ACKED')),
                received_at_ms INTEGER NOT NULL CHECK(received_at_ms > 0),
                acknowledged_at_ms INTEGER
            )
            """.trimIndent()
        )
        db.execSQL("CREATE INDEX messages_session_created_idx ON messages(session_id, created_at_ms)")
        db.execSQL("CREATE INDEX outbox_state_updated_idx ON outbox(state, updated_at_ms)")
        db.execSQL("CREATE INDEX inbox_ack_state_received_idx ON inbox_receipts(ack_state, received_at_ms)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // Never silently discard encrypted conversation state. Schema changes must use explicit,
        // forward-only migrations that preserve messages, ratchet snapshots and prekey records.
        throw IllegalStateException("No safe messaging database migration from $oldVersion to $newVersion is installed.")
    }

    @Synchronized
    fun insertInitialSession(session: StoredMessagingSession) {
        validateSession(session)
        require(session.generation == 0L) { "A newly created native session must start at generation zero." }
        writableDatabase.insertOrThrow(TABLE_SESSIONS, null, sessionValues(session))
    }

    @Synchronized
    fun getSession(sessionId: ByteArray): StoredMessagingSession? {
        requireSessionId(sessionId)
        return readableDatabase.query(
            TABLE_SESSIONS,
            SESSION_COLUMNS,
            "hex(session_id) = ?",
            arrayOf(sessionId.toHex()),
            null,
            null,
            null,
            "1",
        ).use { cursor -> if (cursor.moveToFirst()) cursor.toSession() else null }
    }

    /** Finds the newest persisted session for the exact peer device. Device IDs are UUIDv7 and globally unique. */
    @Synchronized
    fun getSessionForPeerDevice(peerDeviceId: ByteArray): StoredMessagingSession? {
        requireFixedId(peerDeviceId, "peer device ID")
        return readableDatabase.query(
            TABLE_SESSIONS,
            SESSION_COLUMNS,
            "hex(peer_device_id) = ?",
            arrayOf(peerDeviceId.toHex()),
            null,
            null,
            "updated_at_ms DESC",
            "1",
        ).use { cursor -> if (cursor.moveToFirst()) cursor.toSession() else null }
    }

    /** Returns every persisted ratchet session for the exact peer device, newest first. */
    @Synchronized
    fun getSessionsForPeerDevice(peerDeviceId: ByteArray): List<StoredMessagingSession> {
        requireFixedId(peerDeviceId, "peer device ID")
        val result = ArrayList<StoredMessagingSession>()
        readableDatabase.query(
            TABLE_SESSIONS,
            SESSION_COLUMNS,
            "hex(peer_device_id) = ?",
            arrayOf(peerDeviceId.toHex()),
            null,
            null,
            "updated_at_ms DESC, session_id ASC",
            null,
        ).use { cursor ->
            while (cursor.moveToNext()) result.add(cursor.toSession())
        }
        return result
    }
    /** Returns the newest messages for one session in display order. */
    @Synchronized
    fun listMessages(sessionId: ByteArray, limit: Int = 100): List<StoredMessage> {
        requireSessionId(sessionId)
        require(limit in 1..500) { "Message history limit must be between 1 and 500." }
        val result = ArrayList<StoredMessage>()
        readableDatabase.query(
            TABLE_MESSAGES,
            MESSAGE_COLUMNS,
            "hex(session_id) = ?",
            arrayOf(sessionId.toHex()),
            null,
            null,
            "created_at_ms DESC, local_message_id DESC",
            limit.toString(),
        ).use { cursor -> while (cursor.moveToNext()) result.add(cursor.toMessage()) }
        result.reverse()
        return result
    }

    /**
     * First-contact responder commit. The initial generation-zero snapshot, authenticated
     * Message 0, pending gateway ACK receipt and generation-one snapshot are committed in one
     * SQLite transaction. A crash cannot leave a half-created responder session.
     */
    @Synchronized
    fun commitInitialIncomingTransition(
        initialSession: StoredMessagingSession,
        gatewayEnvelopeId: String,
        message: EncryptedMessageDraft,
        pendingEncryptedSnapshot: ByteArray,
    ): IncomingCommitResult {
        validateSession(initialSession)
        require(initialSession.generation == 0L) { "Responder initial session must start at generation zero." }
        validateGatewayEnvelopeId(gatewayEnvelopeId)
        validateMessage(message, StoredMessageDirection.INBOUND)
        require(message.sessionId.contentEquals(initialSession.sessionId)) { "Message/session IDs differ." }
        require(message.generation == 1L) { "First inbound message must advance generation zero to one." }
        require(pendingEncryptedSnapshot.isNotEmpty()) { "Pending encrypted ratchet snapshot is empty." }

        val db = writableDatabase
        db.beginTransaction()
        try {
            if (exists(db, "SELECT 1 FROM inbox_receipts WHERE gateway_envelope_id = ? LIMIT 1", arrayOf(gatewayEnvelopeId))) {
                db.setTransactionSuccessful()
                return IncomingCommitResult.DUPLICATE
            }
            if (exists(db, "SELECT 1 FROM messaging_sessions WHERE hex(session_id) = ? LIMIT 1", arrayOf(initialSession.sessionId.toHex()))) {
                throw StaleSessionGenerationException("A responder session with this first-envelope ID already exists without its gateway receipt.")
            }
            db.insertOrThrow(TABLE_SESSIONS, null, sessionValues(initialSession))
            db.insertOrThrow(TABLE_MESSAGES, null, messageValues(message))
            db.insertOrThrow(
                TABLE_INBOX_RECEIPTS,
                null,
                ContentValues().apply {
                    put("gateway_envelope_id", gatewayEnvelopeId)
                    put("local_message_id", message.localMessageId)
                    put("ack_state", ACK_PENDING)
                    put("received_at_ms", message.createdAtMillis)
                },
            )
            updateSessionSnapshot(
                db,
                initialSession.sessionId,
                expectedGeneration = 0L,
                nextGeneration = 1L,
                encryptedSnapshot = pendingEncryptedSnapshot,
                updatedAtMillis = message.createdAtMillis,
            )
            db.setTransactionSuccessful()
            return IncomingCommitResult.INSERTED
        } finally {
            db.endTransaction()
        }
    }

    @Synchronized
    fun storeSignedPrekey(prekey: StoredSignedPrekey) {
        validateSignedPrekey(prekey)
        writableDatabase.insertWithOnConflict(
            TABLE_SIGNED_PREKEYS,
            null,
            ContentValues().apply {
                put("account_epoch", prekey.accountEpoch)
                put("signed_prekey_id", prekey.signedPrekeyId)
                put("raw_signed_prekey", prekey.rawSignedPrekey.copyOf())
                put("encrypted_private_record", prekey.encryptedPrivateRecord.copyOf())
                put("created_at_ms", prekey.createdAtMillis)
            },
            SQLiteDatabase.CONFLICT_ABORT,
        )
    }

    @Synchronized
    fun getSignedPrekey(accountEpoch: Long, signedPrekeyId: Long): StoredSignedPrekey? {
        requireEpoch(accountEpoch, "account epoch")
        requirePrekeyId(signedPrekeyId)
        return readableDatabase.query(
            TABLE_SIGNED_PREKEYS,
            SIGNED_PREKEY_COLUMNS,
            "account_epoch = ? AND signed_prekey_id = ?",
            arrayOf(accountEpoch.toString(), signedPrekeyId.toString()),
            null,
            null,
            null,
            "1",
        ).use { cursor -> if (cursor.moveToFirst()) cursor.toSignedPrekey() else null }
    }

    /**
     * Atomically stores the encrypted message/body, READY outbox entry and next encrypted ratchet
     * snapshot. The caller must invoke native commitStaged() only after this method returns.
     */
    @Synchronized
    fun commitOutgoingTransition(
        expectedGeneration: Long,
        message: EncryptedMessageDraft,
        pendingEncryptedSnapshot: ByteArray,
    ) {
        validateMessage(message, StoredMessageDirection.OUTBOUND)
        require(message.generation == checkedNextGeneration(expectedGeneration)) {
            "Outgoing message generation must be exactly one greater than the stored generation."
        }
        require(pendingEncryptedSnapshot.isNotEmpty()) { "Pending encrypted ratchet snapshot is empty." }
        commitSessionTransition(expectedGeneration, message, pendingEncryptedSnapshot) { db ->
            db.insertOrThrow(
                TABLE_OUTBOX,
                null,
                ContentValues().apply {
                    put("local_message_id", message.localMessageId)
                    put("state", OutboxState.READY.name)
                    put("attempt_count", 0L)
                    put("updated_at_ms", message.createdAtMillis)
                },
            )
        }
    }

    /**
     * Atomically stores an authenticated inbound message, its pending ACK receipt, and the next
     * encrypted ratchet snapshot. A repeated gateway ID is a no-op and does not advance the ratchet.
     * If DUPLICATE is returned, the caller must discard the native staged transition.
     */
    @Synchronized
    fun commitIncomingTransition(
        expectedGeneration: Long,
        gatewayEnvelopeId: String,
        message: EncryptedMessageDraft,
        pendingEncryptedSnapshot: ByteArray,
    ): IncomingCommitResult {
        validateGatewayEnvelopeId(gatewayEnvelopeId)
        validateMessage(message, StoredMessageDirection.INBOUND)
        require(message.generation == checkedNextGeneration(expectedGeneration)) {
            "Incoming message generation must be exactly one greater than the stored generation."
        }
        require(pendingEncryptedSnapshot.isNotEmpty()) { "Pending encrypted ratchet snapshot is empty." }

        val db = writableDatabase
        db.beginTransaction()
        try {
            if (exists(db, "SELECT 1 FROM inbox_receipts WHERE gateway_envelope_id = ? LIMIT 1", arrayOf(gatewayEnvelopeId))) {
                db.setTransactionSuccessful()
                return IncomingCommitResult.DUPLICATE
            }
            assertCurrentGeneration(db, message.sessionId, expectedGeneration)
            db.insertOrThrow(TABLE_MESSAGES, null, messageValues(message))
            db.insertOrThrow(
                TABLE_INBOX_RECEIPTS,
                null,
                ContentValues().apply {
                    put("gateway_envelope_id", gatewayEnvelopeId)
                    put("local_message_id", message.localMessageId)
                    put("ack_state", ACK_PENDING)
                    put("received_at_ms", message.createdAtMillis)
                },
            )
            updateSessionSnapshot(db, message.sessionId, expectedGeneration, message.generation, pendingEncryptedSnapshot, message.createdAtMillis)
            db.setTransactionSuccessful()
            return IncomingCommitResult.INSERTED
        } finally {
            db.endTransaction()
        }
    }

    /** Returns true only when the gateway ID has already been durably authenticated and stored. */
    @Synchronized
    fun hasReceivedGatewayEnvelope(gatewayEnvelopeId: String): Boolean {
        validateGatewayEnvelopeId(gatewayEnvelopeId)
        return exists(
            readableDatabase,
            "SELECT 1 FROM inbox_receipts WHERE gateway_envelope_id = ? LIMIT 1",
            arrayOf(gatewayEnvelopeId),
        )
    }

    @Synchronized
    fun getMessage(localMessageId: String): StoredMessage? {
        validateLocalMessageId(localMessageId)
        return readableDatabase.query(
            TABLE_MESSAGES,
            MESSAGE_COLUMNS,
            "local_message_id = ?",
            arrayOf(localMessageId),
            null,
            null,
            null,
            "1",
        ).use { cursor -> if (cursor.moveToFirst()) cursor.toMessage() else null }
    }

    @Synchronized
    fun listReadyOutbox(limit: Int = 50): List<ReadyOutboxMessage> {
        require(limit in 1..100) { "Outbox limit must be between 1 and 100." }
        val output = ArrayList<ReadyOutboxMessage>()
        readableDatabase.rawQuery(
            """
            SELECT o.local_message_id, m.envelope_wire, o.attempt_count
            FROM outbox o JOIN messages m ON m.local_message_id = o.local_message_id
            WHERE o.state = 'READY'
            ORDER BY o.updated_at_ms ASC, o.local_message_id ASC
            LIMIT ?
            """.trimIndent(),
            arrayOf(limit.toString()),
        ).use { cursor ->
            while (cursor.moveToNext()) {
                output.add(
                    ReadyOutboxMessage(
                        localMessageId = cursor.getString(0),
                        envelopeWire = cursor.getBlob(1).copyOf(),
                        attemptCount = cursor.getLong(2),
                    ),
                )
            }
        }
        return output
    }


    @Synchronized
    fun listDeliveryUnknownOutbox(maxAttempts: Int = 5, limit: Int = 20): List<ReadyOutboxMessage> {
        val db = readableDatabase
        val items = mutableListOf<ReadyOutboxMessage>()
        db.rawQuery(
            """
            SELECT o.local_message_id, m.envelope_wire, o.attempt_count
            FROM outbox o
            INNER JOIN messages m ON m.local_message_id = o.local_message_id
            WHERE o.state = 'DELIVERY_UNKNOWN' AND o.attempt_count < ?
            ORDER BY o.updated_at_ms ASC
            LIMIT ?
            """.trimIndent(),
            arrayOf(maxAttempts.toString(), limit.toString()),
        ).use { cursor ->
            while (cursor.moveToNext()) {
                items.add(
                    ReadyOutboxMessage(
                        localMessageId = cursor.getString(0),
                        envelopeWire = cursor.getBlob(1),
                        attemptCount = cursor.getLong(2),
                    ),
                )
            }
        }
        return items
    }

    @Synchronized
    fun beginRetryOutboxAttempt(localMessageId: String, attemptedAtMillis: Long): Boolean {
        val db = writableDatabase
        db.execSQL(
            """
            UPDATE outbox
            SET state = 'ATTEMPTING',
                attempt_count = attempt_count + 1,
                attempt_started_at_ms = ?,
                updated_at_ms = ?
            WHERE local_message_id = ? AND state IN ('READY', 'DELIVERY_UNKNOWN')
            """.trimIndent(),
            arrayOf(attemptedAtMillis, attemptedAtMillis, localMessageId),
        )
        return getOutboxStatus(localMessageId)?.state == OutboxState.ATTEMPTING
    }

    @Synchronized
    fun getOutboxStatus(localMessageId: String): StoredOutboxStatus? {
        validateLocalMessageId(localMessageId)
        return readableDatabase.rawQuery(
            "SELECT state, attempt_count, gateway_envelope_id, last_error_code FROM outbox WHERE local_message_id = ? LIMIT 1",
            arrayOf(localMessageId),
        ).use { cursor ->
            if (!cursor.moveToFirst()) return@use null
            StoredOutboxStatus(
                state = OutboxState.valueOf(cursor.getString(0)),
                attemptCount = cursor.getLong(1),
                gatewayEnvelopeId = if (cursor.isNull(2)) null else cursor.getString(2),
                lastErrorCode = if (cursor.isNull(3)) null else cursor.getString(3),
            )
        }
    }

    /**
     * Persist ATTEMPTING before network I/O. After a process crash, that state is ambiguous and
     * must not be automatically retried because the gateway has no idempotency key contract.
     */
    @Synchronized
    fun beginOutboxAttempt(localMessageId: String, attemptedAtMillis: Long): Boolean {
        validateLocalMessageId(localMessageId)
        require(attemptedAtMillis > 0L) { "Attempt timestamp must be positive." }
        val db = writableDatabase
        db.beginTransaction()
        try {
            val changed = db.update(
                TABLE_OUTBOX,
                ContentValues().apply {
                    put("state", OutboxState.ATTEMPTING.name)
                    put("attempt_started_at_ms", attemptedAtMillis)
                    put("updated_at_ms", attemptedAtMillis)
                },
                "local_message_id = ? AND state = ?",
                arrayOf(localMessageId, OutboxState.READY.name),
            )
            if (changed == 1) {
                db.execSQL(
                    "UPDATE outbox SET attempt_count = attempt_count + 1 WHERE local_message_id = ?",
                    arrayOf(localMessageId),
                )
            }
            db.setTransactionSuccessful()
            return changed == 1
        } finally {
            db.endTransaction()
        }
    }

    @Synchronized
    fun markOutboxSubmitted(
        localMessageId: String,
        gatewayEnvelopeId: String,
        submittedAtMillis: Long,
    ) {
        validateLocalMessageId(localMessageId)
        validateGatewayEnvelopeId(gatewayEnvelopeId)
        require(submittedAtMillis > 0L) { "Submission timestamp must be positive." }
        val db = writableDatabase
        db.beginTransaction()
        try {
            val values = ContentValues().apply {
                put("state", OutboxState.SUBMITTED.name)
                put("gateway_envelope_id", gatewayEnvelopeId)
                putNull("last_error_code")
                put("updated_at_ms", submittedAtMillis)
            }
            val changed = db.update(
                TABLE_OUTBOX,
                values,
                "local_message_id = ? AND state = ?",
                arrayOf(localMessageId, OutboxState.ATTEMPTING.name),
            )
            check(changed == 1) { "Outbox item is not in ATTEMPTING state." }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    @Synchronized
    fun markOutboxDeliveryUnknown(localMessageId: String, errorCode: String, updatedAtMillis: Long) {
        validateLocalMessageId(localMessageId)
        require(errorCode.matches(Regex("^[A-Z0-9_]{1,$MAX_ERROR_CODE_LENGTH}$"))) {
            "Outbox error code must use 1..$MAX_ERROR_CODE_LENGTH uppercase letters, digits or underscores."
        }
        require(updatedAtMillis > 0L) { "Outbox timestamp must be positive." }
        val changed = writableDatabase.update(
            TABLE_OUTBOX,
            ContentValues().apply {
                put("state", OutboxState.DELIVERY_UNKNOWN.name)
                put("last_error_code", errorCode)
                put("updated_at_ms", updatedAtMillis)
            },
            "local_message_id = ? AND state = ?",
            arrayOf(localMessageId, OutboxState.ATTEMPTING.name),
        )
        check(changed == 1) { "Outbox item is not in ATTEMPTING state." }
    }

    /** Convert attempts interrupted by process death into an explicit non-retryable state. */
    @Synchronized
    fun recoverAmbiguousOutboxAttempts(recoveredAtMillis: Long): Int {
        require(recoveredAtMillis > 0L) { "Recovery timestamp must be positive." }
        return writableDatabase.update(
            TABLE_OUTBOX,
            ContentValues().apply {
                put("state", OutboxState.DELIVERY_UNKNOWN.name)
                put("last_error_code", "PROCESS_INTERRUPTED_DURING_SEND")
                put("updated_at_ms", recoveredAtMillis)
            },
            "state = ?",
            arrayOf(OutboxState.ATTEMPTING.name),
        )
    }

    @Synchronized
    fun listPendingInboundAcknowledgements(limit: Int = 50): List<String> {
        require(limit in 1..100) { "ACK limit must be between 1 and 100." }
        val ids = ArrayList<String>()
        readableDatabase.rawQuery(
            "SELECT gateway_envelope_id FROM inbox_receipts WHERE ack_state = ? ORDER BY received_at_ms ASC LIMIT ?",
            arrayOf(ACK_PENDING, limit.toString()),
        ).use { cursor -> while (cursor.moveToNext()) ids.add(cursor.getString(0)) }
        return ids
    }

    @Synchronized
    fun markInboundAcknowledged(gatewayEnvelopeId: String, acknowledgedAtMillis: Long): Boolean {
        validateGatewayEnvelopeId(gatewayEnvelopeId)
        require(acknowledgedAtMillis > 0L) { "ACK timestamp must be positive." }
        return writableDatabase.update(
            TABLE_INBOX_RECEIPTS,
            ContentValues().apply {
                put("ack_state", ACKED)
                put("acknowledged_at_ms", acknowledgedAtMillis)
            },
            "gateway_envelope_id = ? AND ack_state = ?",
            arrayOf(gatewayEnvelopeId, ACK_PENDING),
        ) == 1
    }

    private fun commitSessionTransition(
        expectedGeneration: Long,
        message: EncryptedMessageDraft,
        pendingEncryptedSnapshot: ByteArray,
        extraWrites: (SQLiteDatabase) -> Unit,
    ) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            assertCurrentGeneration(db, message.sessionId, expectedGeneration)
            db.insertOrThrow(TABLE_MESSAGES, null, messageValues(message))
            extraWrites(db)
            updateSessionSnapshot(db, message.sessionId, expectedGeneration, message.generation, pendingEncryptedSnapshot, message.createdAtMillis)
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    private fun assertCurrentGeneration(db: SQLiteDatabase, sessionId: ByteArray, expectedGeneration: Long) {
        val current = db.rawQuery(
            "SELECT generation FROM messaging_sessions WHERE hex(session_id) = ? LIMIT 1",
            arrayOf(sessionId.toHex()),
        ).use { cursor ->
            if (!cursor.moveToFirst()) throw IllegalStateException("Messaging session does not exist.")
            cursor.getLong(0)
        }
        if (current != expectedGeneration) {
            throw StaleSessionGenerationException("Session generation changed: expected $expectedGeneration, found $current.")
        }
    }

    private fun updateSessionSnapshot(
        db: SQLiteDatabase,
        sessionId: ByteArray,
        expectedGeneration: Long,
        nextGeneration: Long,
        encryptedSnapshot: ByteArray,
        updatedAtMillis: Long,
    ) {
        val changed = db.update(
            TABLE_SESSIONS,
            ContentValues().apply {
                put("generation", nextGeneration)
                put("encrypted_snapshot", encryptedSnapshot.copyOf())
                put("updated_at_ms", updatedAtMillis)
            },
            "hex(session_id) = ? AND generation = ?",
            arrayOf(sessionId.toHex(), expectedGeneration.toString()),
        )
        if (changed != 1) {
            throw StaleSessionGenerationException("Session changed during ratchet transaction.")
        }
    }

    private fun exists(db: SQLiteDatabase, sql: String, args: Array<String>): Boolean =
        db.rawQuery(sql, args).use { it.moveToFirst() }

    private fun sessionValues(session: StoredMessagingSession) = ContentValues().apply {
        put("session_id", session.sessionId.copyOf())
        put("peer_account_id", session.peerAccountId.copyOf())
        put("peer_device_id", session.peerDeviceId.copyOf())
        put("local_epoch", session.localEpoch)
        put("peer_epoch", session.peerEpoch)
        put("generation", session.generation)
        put("encrypted_snapshot", session.encryptedSnapshot.copyOf())
        put("first_prekey_header", session.firstPrekeyHeader.copyOf())
        put("created_at_ms", session.createdAtMillis)
        put("updated_at_ms", session.updatedAtMillis)
    }

    private fun messageValues(message: EncryptedMessageDraft) = ContentValues().apply {
        put("local_message_id", message.localMessageId)
        put("session_id", message.sessionId.copyOf())
        put("protocol_envelope_id", message.protocolEnvelopeId.copyOf())
        put("direction", message.direction.name)
        put("generation", message.generation)
        put("encrypted_body", message.encryptedBody.copyOf())
        put("envelope_wire", message.envelopeWire.copyOf())
        put("created_at_ms", message.createdAtMillis)
    }

    private fun validateSession(session: StoredMessagingSession) {
        requireSessionId(session.sessionId)
        requireFixedId(session.peerAccountId, "peer account ID")
        requireFixedId(session.peerDeviceId, "peer device ID")
        requireEpoch(session.localEpoch, "local epoch")
        requireEpoch(session.peerEpoch, "peer epoch")
        require(session.generation >= 0L) { "Session generation cannot be negative." }
        require(session.encryptedSnapshot.isNotEmpty() && session.encryptedSnapshot.size <= MAX_SNAPSHOT_BYTES) {
            "Encrypted ratchet snapshot has an invalid size."
        }
        require(session.firstPrekeyHeader.size <= MAX_PREKEY_HEADER_BYTES) { "First prekey header is too large." }
        require(session.createdAtMillis > 0L && session.updatedAtMillis >= session.createdAtMillis) {
            "Session timestamps are invalid."
        }
    }

    private fun validateSignedPrekey(prekey: StoredSignedPrekey) {
        requireEpoch(prekey.accountEpoch, "account epoch")
        requirePrekeyId(prekey.signedPrekeyId)
        require(prekey.rawSignedPrekey.isNotEmpty() && prekey.rawSignedPrekey.size <= MAX_PREKEY_RECORD_BYTES) {
            "Signed prekey public record has an invalid size."
        }
        require(prekey.encryptedPrivateRecord.isNotEmpty() && prekey.encryptedPrivateRecord.size <= MAX_PREKEY_RECORD_BYTES) {
            "Encrypted signed prekey private record has an invalid size."
        }
        require(prekey.createdAtMillis > 0L) { "Signed prekey timestamp must be positive." }
    }

    private fun validateMessage(message: EncryptedMessageDraft, expectedDirection: StoredMessageDirection) {
        validateLocalMessageId(message.localMessageId)
        requireSessionId(message.sessionId)
        requireFixedId(message.protocolEnvelopeId, "protocol envelope ID")
        require(message.direction == expectedDirection) { "Message direction does not match the operation." }
        require(message.generation > 0L) { "Message generation must be positive." }
        require(message.encryptedBody.isNotEmpty() && message.encryptedBody.size <= MAX_ENCRYPTED_BODY_BYTES) {
            "Encrypted message body has an invalid size."
        }
        require(message.envelopeWire.isNotEmpty() && message.envelopeWire.size <= MAX_ENVELOPE_BYTES) {
            "Message envelope has an invalid size."
        }
        require(message.createdAtMillis > 0L) { "Message timestamp must be positive." }
    }

    private fun requireSessionId(bytes: ByteArray) = requireFixedId(bytes, "session ID")

    private fun requireFixedId(bytes: ByteArray, name: String) {
        require(bytes.size == FIXED_ID_BYTES) { "$name must be $FIXED_ID_BYTES bytes." }
    }

    private fun requireEpoch(value: Long, name: String) {
        require(value in 1L..MAX_U32) { "$name is outside the protocol u32 range." }
    }

    private fun requirePrekeyId(value: Long) {
        require(value in 1L..MAX_U32) { "Signed prekey ID is outside the protocol u32 range." }
    }

    private fun checkedNextGeneration(current: Long): Long {
        require(current >= 0L && current < Long.MAX_VALUE) { "Session generation is exhausted or invalid." }
        return current + 1L
    }

    private fun validateLocalMessageId(value: String) {
        require(value.length == 36 && runCatching { UUID.fromString(value) }.isSuccess) {
            "Local message ID must be a UUID."
        }
    }

    private fun validateGatewayEnvelopeId(value: String) {
        validateLocalMessageId(value)
    }

    private fun ByteArray.toHex(): String = buildString(size * 2) {
        for (byte in this@toHex) append("%02X".format(byte.toInt() and 0xFF))
    }

    private fun Cursor.toSession() = StoredMessagingSession(
        sessionId = getBlob(getColumnIndexOrThrow("session_id")).copyOf(),
        peerAccountId = getBlob(getColumnIndexOrThrow("peer_account_id")).copyOf(),
        peerDeviceId = getBlob(getColumnIndexOrThrow("peer_device_id")).copyOf(),
        localEpoch = getLong(getColumnIndexOrThrow("local_epoch")),
        peerEpoch = getLong(getColumnIndexOrThrow("peer_epoch")),
        generation = getLong(getColumnIndexOrThrow("generation")),
        encryptedSnapshot = getBlob(getColumnIndexOrThrow("encrypted_snapshot")).copyOf(),
        firstPrekeyHeader = getBlob(getColumnIndexOrThrow("first_prekey_header")).copyOf(),
        createdAtMillis = getLong(getColumnIndexOrThrow("created_at_ms")),
        updatedAtMillis = getLong(getColumnIndexOrThrow("updated_at_ms")),
    )

    private fun Cursor.toSignedPrekey() = StoredSignedPrekey(
        accountEpoch = getLong(getColumnIndexOrThrow("account_epoch")),
        signedPrekeyId = getLong(getColumnIndexOrThrow("signed_prekey_id")),
        rawSignedPrekey = getBlob(getColumnIndexOrThrow("raw_signed_prekey")).copyOf(),
        encryptedPrivateRecord = getBlob(getColumnIndexOrThrow("encrypted_private_record")).copyOf(),
        createdAtMillis = getLong(getColumnIndexOrThrow("created_at_ms")),
    )

    private fun Cursor.toMessage() = StoredMessage(
        localMessageId = getString(getColumnIndexOrThrow("local_message_id")),
        sessionId = getBlob(getColumnIndexOrThrow("session_id")).copyOf(),
        protocolEnvelopeId = getBlob(getColumnIndexOrThrow("protocol_envelope_id")).copyOf(),
        direction = StoredMessageDirection.valueOf(getString(getColumnIndexOrThrow("direction"))),
        generation = getLong(getColumnIndexOrThrow("generation")),
        encryptedBody = getBlob(getColumnIndexOrThrow("encrypted_body")).copyOf(),
        envelopeWire = getBlob(getColumnIndexOrThrow("envelope_wire")).copyOf(),
        createdAtMillis = getLong(getColumnIndexOrThrow("created_at_ms")),
    )

    private companion object {
        const val DATABASE_NAME = "private-messenger-v1.db"
        const val DATABASE_VERSION = 1
        const val FIXED_ID_BYTES = 16
        const val MAX_U32 = 4_294_967_295L
        const val MAX_ENVELOPE_BYTES = 65_552
        const val MAX_ENCRYPTED_BODY_BYTES = 131_072
        const val MAX_SNAPSHOT_BYTES = 1_048_576
        const val MAX_PREKEY_HEADER_BYTES = 4_096
        const val MAX_PREKEY_RECORD_BYTES = 4_096
        const val MAX_ERROR_CODE_LENGTH = 64
        const val TABLE_SESSIONS = "messaging_sessions"
        const val TABLE_SIGNED_PREKEYS = "signed_prekeys"
        const val TABLE_MESSAGES = "messages"
        const val TABLE_OUTBOX = "outbox"
        const val TABLE_INBOX_RECEIPTS = "inbox_receipts"
        const val ACK_PENDING = "ACK_PENDING"
        const val ACKED = "ACKED"
        val SESSION_COLUMNS = arrayOf(
            "session_id", "peer_account_id", "peer_device_id", "local_epoch", "peer_epoch",
            "generation", "encrypted_snapshot", "first_prekey_header", "created_at_ms", "updated_at_ms",
        )
        val SIGNED_PREKEY_COLUMNS = arrayOf(
            "account_epoch", "signed_prekey_id", "raw_signed_prekey", "encrypted_private_record", "created_at_ms",
        )
        val MESSAGE_COLUMNS = arrayOf(
            "local_message_id", "session_id", "protocol_envelope_id", "direction", "generation",
            "encrypted_body", "envelope_wire", "created_at_ms",
        )
    }
}
