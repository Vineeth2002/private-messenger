package org.sovereign.pm.messaging

import android.content.Context
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class LocalMessagingDatabaseTest {
    private lateinit var context: Context
    private lateinit var database: LocalMessagingDatabase

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        context.deleteDatabase(DATABASE_NAME)
        database = LocalMessagingDatabase(context, DATABASE_NAME)
    }

    @After
    fun tearDown() {
        database.close()
        context.deleteDatabase(DATABASE_NAME)
    }

    @Test
    fun initialSessionAndEncryptedSignedPrekeyRoundTripAcrossReopen() {
        val session = initialSession()
        database.insertInitialSession(session)
        val prekey = StoredSignedPrekey(
            accountEpoch = 7,
            signedPrekeyId = 19,
            rawSignedPrekey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            encryptedPrivateRecord = ByteArray(64) { (it + 11).toByte() },
            createdAtMillis = 1_800_000_000_000,
        )
        database.storeSignedPrekey(prekey)

        database.close()
        database = LocalMessagingDatabase(context, DATABASE_NAME)

        val restoredSession = database.getSession(session.sessionId)
            ?: throw AssertionError("Session was not persisted")
        assertArrayEquals(session.sessionId, restoredSession.sessionId)
        assertEquals(0L, restoredSession.generation)
        assertArrayEquals(session.encryptedSnapshot, restoredSession.encryptedSnapshot)
        assertArrayEquals(session.firstPrekeyHeader, restoredSession.firstPrekeyHeader)

        val restoredPrekey = database.getSignedPrekey(7, 19)
            ?: throw AssertionError("Signed prekey was not persisted")
        assertArrayEquals(prekey.rawSignedPrekey, restoredPrekey.rawSignedPrekey)
        assertArrayEquals(prekey.encryptedPrivateRecord, restoredPrekey.encryptedPrivateRecord)
    }

    @Test
    fun outgoingRatchetSnapshotMessageAndOutboxCommitAtomically() {
        database.insertInitialSession(initialSession())
        val message = outboundDraft(generation = 1)
        val nextSnapshot = ByteArray(64) { (it + 0x40).toByte() }

        database.commitOutgoingTransition(
            expectedGeneration = 0,
            message = message,
            pendingEncryptedSnapshot = nextSnapshot,
        )

        val storedSession = database.getSession(SESSION_ID)!!
        assertEquals(1L, storedSession.generation)
        assertArrayEquals(nextSnapshot, storedSession.encryptedSnapshot)

        val storedMessage = database.getMessage(message.localMessageId)!!
        assertEquals(StoredMessageDirection.OUTBOUND, storedMessage.direction)
        assertArrayEquals(message.encryptedBody, storedMessage.encryptedBody)
        assertArrayEquals(message.envelopeWire, storedMessage.envelopeWire)

        val outbox = database.listReadyOutbox()
        assertEquals(1, outbox.size)
        assertEquals(message.localMessageId, outbox.single().localMessageId)
        assertArrayEquals(message.envelopeWire, outbox.single().envelopeWire)
        assertEquals(0L, outbox.single().attemptCount)
    }

    @Test
    fun staleGenerationRollsBackMessageOutboxAndSnapshotTogether() {
        database.insertInitialSession(initialSession())
        val message = outboundDraft(generation = 2)

        assertThrows(StaleSessionGenerationException::class.java) {
            database.commitOutgoingTransition(
                expectedGeneration = 1,
                message = message,
                pendingEncryptedSnapshot = ByteArray(64) { 0x55 },
            )
        }

        assertEquals(0L, database.getSession(SESSION_ID)!!.generation)
        assertNull(database.getMessage(message.localMessageId))
        assertTrue(database.listReadyOutbox().isEmpty())
    }

    @Test
    fun inboundDuplicateDoesNotAdvanceRatchetAndRemainsAckPendingUntilAckSucceeds() {
        database.insertInitialSession(initialSession())
        val gatewayId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        val firstMessage = inboundDraft(generation = 1)

        val first = database.commitIncomingTransition(
            expectedGeneration = 0,
            gatewayEnvelopeId = gatewayId,
            message = firstMessage,
            pendingEncryptedSnapshot = ByteArray(64) { 0x61 },
        )
        assertEquals(IncomingCommitResult.INSERTED, first)
        assertEquals(1L, database.getSession(SESSION_ID)!!.generation)
        assertTrue(database.hasReceivedGatewayEnvelope(gatewayId))
        assertEquals(listOf(gatewayId), database.listPendingInboundAcknowledgements())

        val replayDraft = inboundDraft(generation = 2)
        val duplicate = database.commitIncomingTransition(
            expectedGeneration = 1,
            gatewayEnvelopeId = gatewayId,
            message = replayDraft,
            pendingEncryptedSnapshot = ByteArray(64) { 0x62 },
        )
        assertEquals(IncomingCommitResult.DUPLICATE, duplicate)
        assertEquals(1L, database.getSession(SESSION_ID)!!.generation)
        assertNull(database.getMessage(replayDraft.localMessageId))

        assertTrue(database.markInboundAcknowledged(gatewayId, 1_800_000_000_100))
        assertTrue(database.listPendingInboundAcknowledgements().isEmpty())
        assertFalse(database.markInboundAcknowledged(gatewayId, 1_800_000_000_101))
    }

    @Test
    fun interruptedOutboxAttemptIsNeverReturnedToReadyQueue() {
        database.insertInitialSession(initialSession())
        val message = outboundDraft(generation = 1)
        database.commitOutgoingTransition(
            expectedGeneration = 0,
            message = message,
            pendingEncryptedSnapshot = ByteArray(64) { 0x71 },
        )

        assertTrue(database.beginOutboxAttempt(message.localMessageId, 1_800_000_000_200))
        assertFalse(database.beginOutboxAttempt(message.localMessageId, 1_800_000_000_201))
        assertTrue(database.listReadyOutbox().isEmpty())

        assertEquals(1, database.recoverAmbiguousOutboxAttempts(1_800_000_000_300))
        assertTrue(database.listReadyOutbox().isEmpty())
        val status = database.getOutboxStatus(message.localMessageId)!!
        assertEquals(OutboxState.DELIVERY_UNKNOWN, status.state)
        assertEquals(1L, status.attemptCount)
        assertEquals("PROCESS_INTERRUPTED_DURING_SEND", status.lastErrorCode)
        assertThrows(IllegalStateException::class.java) {
            database.markOutboxSubmitted(
                message.localMessageId,
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                1_800_000_000_400,
            )
        }
    }

    @Test
    fun successfulOutboxReceiptIsPersistedAndCannotBeSubmittedTwice() {
        database.insertInitialSession(initialSession())
        val message = outboundDraft(generation = 1)
        database.commitOutgoingTransition(
            expectedGeneration = 0,
            message = message,
            pendingEncryptedSnapshot = ByteArray(64) { 0x72 },
        )
        assertTrue(database.beginOutboxAttempt(message.localMessageId, 1_800_000_000_200))

        database.markOutboxSubmitted(
            message.localMessageId,
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            1_800_000_000_300,
        )

        assertTrue(database.listReadyOutbox().isEmpty())
        val status = database.getOutboxStatus(message.localMessageId)!!
        assertEquals(OutboxState.SUBMITTED, status.state)
        assertEquals("cccccccc-cccc-4ccc-8ccc-cccccccccccc", status.gatewayEnvelopeId)
        assertEquals(1L, status.attemptCount)
        assertThrows(IllegalStateException::class.java) {
            database.markOutboxSubmitted(
                message.localMessageId,
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                1_800_000_000_400,
            )
        }
    }

    @Test
    fun invalidIdsAndPlainOrEmptyPayloadsAreRejectedBeforeSqlWrites() {
        database.insertInitialSession(initialSession())
        val invalid = outboundDraft(generation = 1).copy(
            protocolEnvelopeId = byteArrayOf(1, 2, 3),
        )
        assertThrows(IllegalArgumentException::class.java) {
            database.commitOutgoingTransition(
                expectedGeneration = 0,
                message = invalid,
                pendingEncryptedSnapshot = ByteArray(64) { 0x33 },
            )
        }
        assertEquals(0L, database.getSession(SESSION_ID)!!.generation)
        assertTrue(database.listReadyOutbox().isEmpty())
    }

    private fun initialSession() = StoredMessagingSession(
        sessionId = SESSION_ID.copyOf(),
        peerAccountId = PEER_ACCOUNT_ID.copyOf(),
        peerDeviceId = PEER_DEVICE_ID.copyOf(),
        localEpoch = 3,
        peerEpoch = 5,
        generation = 0,
        encryptedSnapshot = ByteArray(64) { (it + 1).toByte() },
        firstPrekeyHeader = byteArrayOf(0xA1.toByte(), 0x02),
        createdAtMillis = 1_800_000_000_000,
        updatedAtMillis = 1_800_000_000_000,
    )

    private fun outboundDraft(generation: Long) = EncryptedMessageDraft(
        localMessageId = UUID.randomUUID().toString(),
        sessionId = SESSION_ID.copyOf(),
        protocolEnvelopeId = ByteArray(16) { (it + generation.toByte()).toByte() },
        direction = StoredMessageDirection.OUTBOUND,
        generation = generation,
        encryptedBody = ByteArray(48) { (it + 0x20).toByte() },
        envelopeWire = byteArrayOf(0xA2.toByte(), 0x01, 0x02),
        createdAtMillis = 1_800_000_000_100 + generation,
    )

    private fun inboundDraft(generation: Long) = EncryptedMessageDraft(
        localMessageId = UUID.randomUUID().toString(),
        sessionId = SESSION_ID.copyOf(),
        protocolEnvelopeId = ByteArray(16) { (it + 0x30 + generation.toInt()).toByte() },
        direction = StoredMessageDirection.INBOUND,
        generation = generation,
        encryptedBody = ByteArray(48) { (it + 0x50).toByte() },
        envelopeWire = byteArrayOf(0xA2.toByte(), 0x03, 0x04),
        createdAtMillis = 1_800_000_000_500 + generation,
    )

    private companion object {
        const val DATABASE_NAME = "pm-local-messaging-test.db"
        val SESSION_ID = ByteArray(16) { (it + 1).toByte() }
        val PEER_ACCOUNT_ID = ByteArray(16) { (it + 0x21).toByte() }
        val PEER_DEVICE_ID = ByteArray(16) { (it + 0x41).toByte() }
    }
}
