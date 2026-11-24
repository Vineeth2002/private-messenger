package org.sovereign.pm.messaging

import org.sovereign.pm.crypto.AccountIdentity
import org.sovereign.pm.crypto.NativeMessagingSessionHandle
import org.sovereign.pm.crypto.NativeSignedPrekeyHandle
import org.sovereign.pm.crypto.UniFfiCryptoBridge
import org.sovereign.pm.security.IdentityStore
import java.io.IOException
import java.security.SecureRandom
import java.util.UUID
import java.util.Locale

/** A peer identity locator only. No network-provided keys are considered trusted by this type. */
internal data class PeerPrekeyCandidate(
    val accountId: ByteArray,
    val deviceId: ByteArray,
)

/** Constructed only as the result of an explicit peer-trust verification dependency. */
internal class VerifiedPeerPrekeyMaterial internal constructor(
    val accountId: ByteArray,
    val deviceId: ByteArray,
    val epoch: Long,
    val dskPublicKey: ByteArray,
    val ddhkPublicKey: ByteArray,
    val rawSignedPrekey: ByteArray,
)

/** Production implementation must validate identity certificate, revocation, transparency,
 * rollback state and the signed-prekey binding before returning VerifiedPeerPrekeyMaterial. */
internal fun interface PeerPrekeyVerifier {
    fun verify(candidate: PeerPrekeyCandidate): VerifiedPeerPrekeyMaterial
}

internal data class ReceiveBatchSummary(
    val inserted: Int,
    val duplicates: Int,
    val deferred: Int,
)

internal data class OutboxSubmission(
    val localMessageId: String,
    val gatewayEnvelopeId: String,
    val recipientDeviceId: String,
    val expiresAt: String,
)

/**
 * First local/native integration layer.
 * - stores locally generated signed-prekey private records encrypted under the Storage DEK;
 * - persists initiator session generation zero before first use;
 * - stages outgoing Double Ratchet transitions and atomically writes encrypted body, envelope,
 *   outbox entry and encrypted ratchet snapshot before native commit;
 * - performs one outbound gateway submission attempt; ambiguous sends are never retried.
 *
 * Inbound processing uses a strict canonical MessageEnvelopeV1 reader to extract the protocol
 * envelope ID and prekey metadata. Native Rust remains authoritative for schema validation,
 * Cert_dh verification, X3DH and AEAD authentication.
 */
private fun logInboundDiagnostic(
    stage: String,
    envelopeId: String,
    failure: Exception,
) {
    val detail = failure.message
        ?.replace(Regex("\\s+"), " ")
        ?.take(180)
        .orEmpty()

    android.util.Log.e(
        "PM_INBOUND",
        "stage=$stage envelope=$envelopeId type=${failure.javaClass.simpleName} detail=$detail",
        failure,
    )
}
internal class PersistentMessagingEngine(
    private val identityStore: IdentityStore,
    private val crypto: UniFfiCryptoBridge,
    private val database: LocalMessagingDatabase,
    private val localIdentity: AccountIdentity,
    private val localEpoch: Long,
    private val peerPrekeyVerifier: PeerPrekeyVerifier,
) {
    private val operationLock = Any()

    init {
        require(localIdentity.accountId.size == ID_BYTES) { "Local account ID must be 16 bytes." }
        require(localIdentity.deviceId.size == ID_BYTES) { "Local device ID must be 16 bytes." }
        require(localEpoch in 1L..MAX_U32) { "Local epoch is outside the protocol u32 range." }
        val activeIdentity = crypto.activeAccountIdentity()
        require(activeIdentity.accountId.contentEquals(localIdentity.accountId) &&
            activeIdentity.deviceId.contentEquals(localIdentity.deviceId) &&
            activeIdentity.dskPublicKey.contentEquals(localIdentity.dskPublicKey) &&
            activeIdentity.ddhkPublicKey.contentEquals(localIdentity.ddhkPublicKey)) {
            "Messaging engine identity does not match the active native account."
        }
    }

    /** Generates a local SPK and persists its private record only as native-encrypted bytes. */
    fun generateAndStoreSignedPrekey(signedPrekeyId: Long): ByteArray = synchronized(operationLock) {
        require(signedPrekeyId in 1L..MAX_U32) { "Signed-prekey ID is outside the u32 range." }
        identityStore.withStorageKey { storageKey ->
            val native = crypto.generateSignedPrekeyContext(localEpoch, signedPrekeyId)
            var raw: ByteArray? = null
            var sealedPrivate: ByteArray? = null
            try {
                raw = native.rawSignedPrekey()
                sealedPrivate = native.sealForStorage(storageKey)
                database.storeSignedPrekey(
                    StoredSignedPrekey(
                        accountEpoch = localEpoch,
                        signedPrekeyId = signedPrekeyId,
                        rawSignedPrekey = requireNotNull(raw),
                        encryptedPrivateRecord = requireNotNull(sealedPrivate),
                        createdAtMillis = System.currentTimeMillis(),
                    ),
                )
                requireNotNull(raw).copyOf()
            } finally {
                raw?.fill(0)
                sealedPrivate?.fill(0)
                native.close()
            }
        }
    }

    /**
     * Creates and persists generation-zero initiator state.
     * Peer trust validation is a caller precondition; native SPK validation alone does not prove
     * the peer device certificate, directory freshness, revocation state or transparency history.
     */
    /** Returns the existing local alpha SPK or creates it once. The private part remains native-sealed in SQLite. */
    fun getOrCreateAlphaSignedPrekey(signedPrekeyId: Long = 1L): ByteArray {
        val stored = database.getSignedPrekey(localEpoch, signedPrekeyId)
        return stored?.rawSignedPrekey?.copyOf() ?: generateAndStoreSignedPrekey(signedPrekeyId)
    }

    /** Reuses a persisted session for this paired device; otherwise performs native X3DH initialization. */
    fun getOrCreateAlphaSession(peerCandidate: PeerPrekeyCandidate): StoredMessagingSession {
        val existing = database.getSessionForPeerDevice(peerCandidate.deviceId)
        if (existing != null) {
            require(existing.peerAccountId.contentEquals(peerCandidate.accountId)) {
                "A different account is already associated with this peer device ID."
            }
            return existing
        }
        return createInitiatorSession(peerCandidate)
    }
    fun createInitiatorSession(
        peerCandidate: PeerPrekeyCandidate,
        sessionId: ByteArray = randomId(),
    ): StoredMessagingSession = synchronized(operationLock) {
        // Never pass unverified gateway fields directly to the native X3DH constructor.
        val peer = peerPrekeyVerifier.verify(peerCandidate)
        validatePeer(peer)
        require(sessionId.size == ID_BYTES) { "Session ID must be 16 bytes." }
        identityStore.withStorageKey { storageKey ->
            val native = crypto.createInitiatorMessagingSession(
                peerAccountId = peer.accountId,
                peerDeviceId = peer.deviceId,
                peerEpoch = peer.epoch,
                peerDskPublic = peer.dskPublicKey,
                peerDdhkPublic = peer.ddhkPublicKey,
                peerSignedPrekey = peer.rawSignedPrekey,
                sessionId = sessionId,
                localEpoch = localEpoch,
                storageKey = storageKey,
            )
            var snapshot: ByteArray? = null
            var firstHeader: ByteArray? = null
            try {
                snapshot = native.currentSnapshot()
                firstHeader = native.initialPrekeyHeader()
                val now = System.currentTimeMillis()
                val stored = StoredMessagingSession(
                    sessionId = native.sessionId(),
                    peerAccountId = peer.accountId.copyOf(),
                    peerDeviceId = peer.deviceId.copyOf(),
                    localEpoch = localEpoch,
                    peerEpoch = peer.epoch,
                    generation = 0L,
                    encryptedSnapshot = requireNotNull(snapshot),
                    firstPrekeyHeader = requireNotNull(firstHeader),
                    createdAtMillis = now,
                    updatedAtMillis = now,
                )
                database.insertInitialSession(stored)
                stored.copy(
                    sessionId = stored.sessionId.copyOf(),
                    peerAccountId = stored.peerAccountId.copyOf(),
                    peerDeviceId = stored.peerDeviceId.copyOf(),
                    encryptedSnapshot = stored.encryptedSnapshot.copyOf(),
                    firstPrekeyHeader = stored.firstPrekeyHeader.copyOf(),
                )
            } finally {
                snapshot?.fill(0)
                firstHeader?.fill(0)
                native.close()
            }
        }
    }

    /**
     * Encrypts one outgoing message and commits its encrypted local body, E2EE envelope, outbox
     * entry and pending ratchet snapshot in a single SQLite transaction. Native ratchet state is
     * promoted only after SQLite confirms the transaction.
     */
    /** Call once during process startup before attempting queued sends. */
    fun recoverInterruptedOutboxAttempts(): Int =
        database.recoverAmbiguousOutboxAttempts(System.currentTimeMillis())

    fun encryptAndPersistOutgoing(sessionId: ByteArray, plaintext: ByteArray): String =
        synchronized(operationLock) {
            require(sessionId.size == ID_BYTES) { "Session ID must be 16 bytes." }
            require(plaintext.isNotEmpty() && plaintext.size <= MAX_PLAINTEXT_BYTES) {
                "Message plaintext is empty or exceeds the configured limit."
            }
            val storedSession = database.getSession(sessionId)
                ?: throw IllegalArgumentException("Messaging session does not exist.")
            check(storedSession.localEpoch == localEpoch) { "Stored session belongs to a different local epoch." }
            val nextGeneration = Math.addExact(storedSession.generation, 1L)
            val localMessageId = UUID.randomUUID().toString()
            // First Message 0 uses session_id as envelope_id. The responder derives the same
            // session identifier from the authenticated first envelope, so no new wire field is needed.
            val protocolEnvelopeId = if (
                storedSession.generation == 0L && storedSession.firstPrekeyHeader.isNotEmpty()
            ) storedSession.sessionId.copyOf() else randomId()
            val plaintextCopy = plaintext.copyOf()

            try {
                identityStore.withStorageKey { storageKey ->
                    val native = crypto.restoreMessagingSession(
                        peerAccountId = storedSession.peerAccountId,
                        peerDeviceId = storedSession.peerDeviceId,
                        localEpoch = storedSession.localEpoch,
                        peerEpoch = storedSession.peerEpoch,
                        sessionId = storedSession.sessionId,
                        generation = storedSession.generation,
                        encryptedSnapshot = storedSession.encryptedSnapshot,
                        firstPrekeyHeader = storedSession.firstPrekeyHeader,
                        storageKey = storageKey,
                    )
                    var envelopeWire: ByteArray? = null
                    var encryptedBody: ByteArray? = null
                    var pendingSnapshot: ByteArray? = null
                    try {
                        envelopeWire = native.stageEncryptMessage(protocolEnvelopeId, plaintextCopy)
                        encryptedBody = native.sealLocalMessageBody(nextGeneration, plaintextCopy)
                        pendingSnapshot = native.pendingSnapshot()
                        val draft = EncryptedMessageDraft(
                            localMessageId = localMessageId,
                            sessionId = storedSession.sessionId.copyOf(),
                            protocolEnvelopeId = protocolEnvelopeId.copyOf(),
                            direction = StoredMessageDirection.OUTBOUND,
                            generation = nextGeneration,
                            encryptedBody = requireNotNull(encryptedBody),
                            envelopeWire = requireNotNull(envelopeWire),
                            createdAtMillis = System.currentTimeMillis(),
                        )
                        try {
                            database.commitOutgoingTransition(
                                expectedGeneration = storedSession.generation,
                                message = draft,
                                pendingEncryptedSnapshot = requireNotNull(pendingSnapshot),
                            )
                        } catch (failure: Throwable) {
                            runCatching { native.discardStaged() }
                                .onFailure { failure.addSuppressed(it) }
                            throw failure
                        }
                        // SQLite is durable at this point. The saved snapshot is authoritative
                        // even if this in-memory promotion fails or the process stops afterward.
                        native.commitStaged()
                        localMessageId
                    } finally {
                        envelopeWire?.fill(0)
                        encryptedBody?.fill(0)
                        pendingSnapshot?.fill(0)
                        native.close()
                    }
                }
            } finally {
                plaintextCopy.fill(0)
                protocolEnvelopeId.fill(0)
            }
        }

    /** Restores a local signed-prekey handle from its encrypted SQLite record. Caller must close it. */
    fun restoreLocalSignedPrekey(signedPrekeyId: Long): NativeSignedPrekeyHandle {
        val stored = database.getSignedPrekey(localEpoch, signedPrekeyId)
            ?: throw IllegalArgumentException("Local signed prekey does not exist.")
        return identityStore.withStorageKey { storageKey ->
            crypto.restoreSignedPrekeyContext(
                rawSignedPrekey = stored.rawSignedPrekey,
                encryptedPrivateRecord = stored.encryptedPrivateRecord,
                storageKey = storageKey,
            )
        }
    }

    /**
     * Opens one locally encrypted body for display. The returned plaintext belongs to the caller
     * and must be zeroed after use. Database contents remain encrypted at rest.
     */
    fun openStoredMessageBody(sessionId: ByteArray, localMessageId: String): ByteArray =
        synchronized(operationLock) {
            require(sessionId.size == ID_BYTES) { "Session ID must be 16 bytes." }
            val message = database.getMessage(localMessageId)
                ?: throw IllegalArgumentException("Local message does not exist.")
            require(message.sessionId.contentEquals(sessionId)) {
                "Local message does not belong to the requested session."
            }
            val storedSession = database.getSession(sessionId)
                ?: throw IllegalStateException("Messaging session does not exist.")
            identityStore.withStorageKey { storageKey ->
                val native = crypto.restoreMessagingSession(
                    peerAccountId = storedSession.peerAccountId,
                    peerDeviceId = storedSession.peerDeviceId,
                    localEpoch = storedSession.localEpoch,
                    peerEpoch = storedSession.peerEpoch,
                    sessionId = storedSession.sessionId,
                    generation = storedSession.generation,
                    encryptedSnapshot = storedSession.encryptedSnapshot,
                    firstPrekeyHeader = storedSession.firstPrekeyHeader,
                    storageKey = storageKey,
                )
                try {
                    native.openLocalMessageBody(message.generation, message.encryptedBody)
                } finally {
                    native.close()
                }
            }
        }

    /**
     * Makes one non-retryable network attempt for the oldest READY item. The ATTEMPTING marker is
     * committed before the HTTP request; any ambiguous outcome becomes DELIVERY_UNKNOWN.
     */

    fun reconcileDeliveryUnknownOutbox(
        client: DeviceMessageHttpClient,
        maxAttempts: Int = 5,
    ): Int = synchronized(operationLock) {
        var reconciled = 0
        val items = database.listDeliveryUnknownOutbox(maxAttempts = maxAttempts)
        for (item in items) {
            try {
                if (!database.beginRetryOutboxAttempt(item.localMessageId, System.currentTimeMillis())) {
                    continue
                }
                val storedMessage = database.getMessage(item.localMessageId) ?: continue
                val session = database.getSession(storedMessage.sessionId) ?: continue
                val receipt = client.sendEnvelope(item.envelopeWire)
                val expectedRecipient = uuidFromBytes(session.peerDeviceId)
                if (receipt.recipientDeviceId.equals(expectedRecipient, ignoreCase = true)) {
                    database.markOutboxSubmitted(
                        item.localMessageId,
                        receipt.envelopeId,
                        System.currentTimeMillis(),
                    )
                    reconciled++
                } else {
                    database.markOutboxDeliveryUnknown(
                        item.localMessageId,
                        "RECIPIENT_MISMATCH",
                        System.currentTimeMillis(),
                    )
                }
            } catch (failure: Exception) {
                database.markOutboxDeliveryUnknown(
                    item.localMessageId,
                    safeErrorCode(failure),
                    System.currentTimeMillis(),
                )
            } finally {
                item.envelopeWire.fill(0)
            }
        }
        reconciled
    }

    fun submitNextReadyOutbox(client: DeviceMessageHttpClient): OutboxSubmission? =
        synchronized(operationLock) {
            val item = database.listReadyOutbox(limit = 1).firstOrNull() ?: return null
            val now = System.currentTimeMillis()
            if (!database.beginOutboxAttempt(item.localMessageId, now)) return null
            try {
                val storedMessage = database.getMessage(item.localMessageId)
                    ?: throw IllegalStateException("Outbox message row is missing.")
                val session = database.getSession(storedMessage.sessionId)
                    ?: throw IllegalStateException("Outbox session row is missing.")
                val receipt = client.sendEnvelope(item.envelopeWire)
                val expectedRecipient = uuidFromBytes(session.peerDeviceId)
                if (!receipt.recipientDeviceId.equals(expectedRecipient, ignoreCase = true)) {
                    database.markOutboxDeliveryUnknown(
                        item.localMessageId,
                        "RECIPIENT_MISMATCH",
                        System.currentTimeMillis(),
                    )
                    throw IOException("Gateway accepted the message for an unexpected recipient device.")
                }
                database.markOutboxSubmitted(
                    item.localMessageId,
                    receipt.envelopeId,
                    System.currentTimeMillis(),
                )
                OutboxSubmission(
                    localMessageId = item.localMessageId,
                    gatewayEnvelopeId = receipt.envelopeId,
                    recipientDeviceId = receipt.recipientDeviceId,
                    expiresAt = receipt.expiresAt,
                )
            } catch (failure: Exception) {
                val status = runCatching { database.getOutboxStatus(item.localMessageId) }.getOrNull()
                if (status?.state == OutboxState.ATTEMPTING) {
                    database.markOutboxDeliveryUnknown(
                        item.localMessageId,
                        safeErrorCode(failure),
                        System.currentTimeMillis(),
                    )
                }
                throw failure
            } finally {
                item.envelopeWire.fill(0)
            }
        }

    /**
     * Processes gateway inbox items. A message is acknowledged only after its encrypted body,
     * message row, pending ACK receipt and ratchet snapshot are durably committed in SQLite.
     * Repeated gateway IDs are acknowledged without advancing the ratchet a second time.
     */
    fun processIncomingMessages(
        client: DeviceMessageHttpClient,
        peerTrust: InboundPeerTrustVerifier,
        limit: Int = 50,
    ): ReceiveBatchSummary = synchronized(operationLock) {
        require(limit in 1..100)
        var inserted = 0
        var duplicates = 0
        var deferred = 0

        // First retry ACKs committed by an earlier poll. Network failure leaves them pending.
        deferred += retryPendingInboundAcknowledgementsLocked(client)

        val fetched = client.fetchMessages(limit)
        for (fetchedMessage in fetched) {
            val wire = fetchedMessage.envelopeCbor
            try {
                if (database.hasReceivedGatewayEnvelope(fetchedMessage.envelopeId)) {
                    // Durable receipt already exists. Re-ACK; never touch the ratchet.
                    try {
                        client.acknowledgeMessage(fetchedMessage.envelopeId)
                        database.markInboundAcknowledged(fetchedMessage.envelopeId, System.currentTimeMillis())
                        duplicates++
                    } catch (failure: Exception) {
                        logInboundDiagnostic(
                            "duplicate-acknowledgement",
                            fetchedMessage.envelopeId,
                            failure,
                        )
                        deferred++
                    }
                    continue
                }

                val metadata = MessageEnvelopeV1Wire.decode(wire, crypto::decodeStrictCanonical)
                require(metadata.recipientDeviceId.contentEquals(localIdentity.deviceId)) {
                    "Fetched envelope is addressed to another device."
                }
                require(metadata.envelopeId.isNotEmpty())

                val commit = if (metadata.isPrekeyHandshake) {
                    commitFirstContactMessage(metadata, fetchedMessage, wire, peerTrust)
                } else {
                    commitEstablishedSessionMessage(metadata, fetchedMessage, wire, peerTrust)
                }
                when (commit) {
                    IncomingCommitResult.INSERTED -> inserted++
                    IncomingCommitResult.DUPLICATE -> duplicates++
                }

                // ACK only after SQLite commit and native staged-state promotion.
                try {
                    client.acknowledgeMessage(fetchedMessage.envelopeId)
                    database.markInboundAcknowledged(fetchedMessage.envelopeId, System.currentTimeMillis())
                } catch (failure: Exception) {
                    logInboundDiagnostic(
                        "post-commit-acknowledgement",
                        fetchedMessage.envelopeId,
                        failure,
                    )
                    deferred++
                }
            } catch (failure: Exception) {
                logInboundDiagnostic(
                    "receive-envelope-processing",
                    fetchedMessage.envelopeId,
                    failure,
                )
                // Leave an invalid, untrusted, or not-yet-processable envelope unacknowledged.
                // The caller receives a deferred count; no plaintext is surfaced to the UI.
                deferred++
            } finally {
                wire.fill(0)
            }
        }
        ReceiveBatchSummary(inserted, duplicates, deferred)
    }

    /** Retry only ACK_PENDING receipts. A successful gateway ACK is followed by local ACKED state. */
    fun retryPendingInboundAcknowledgements(client: DeviceMessageHttpClient): Int =
        synchronized(operationLock) { retryPendingInboundAcknowledgementsLocked(client) }

    private fun retryPendingInboundAcknowledgementsLocked(client: DeviceMessageHttpClient): Int {
        var deferred = 0
        for (gatewayEnvelopeId in database.listPendingInboundAcknowledgements(limit = 100)) {
            try {
                client.acknowledgeMessage(gatewayEnvelopeId)
                database.markInboundAcknowledged(gatewayEnvelopeId, System.currentTimeMillis())
            } catch (failure: Exception) {
                logInboundDiagnostic(
                    "pending-acknowledgement-retry",
                    gatewayEnvelopeId,
                    failure,
                )
                deferred++
            }
        }
        return deferred
    }

    private fun commitFirstContactMessage(
        metadata: MessageEnvelopeMetadataV1,
        fetched: FetchedDeviceMessage,
        wire: ByteArray,
        peerTrust: InboundPeerTrustVerifier,
    ): IncomingCommitResult {
        val header = metadata.prekeyHeader ?: throw IllegalArgumentException("Prekey header is missing.")
        val peer = peerTrust.verifyFirstContact(metadata, header)
        require(peer.accountId.contentEquals(header.senderAccountId))
        require(peer.deviceId.contentEquals(metadata.senderDeviceId))
        require(peer.epoch == header.senderAccountEpoch)
        require(peer.dskPublicKey.contentEquals(header.senderDskPublicKey))
        require(peer.ddhkPublicKey.contentEquals(header.senderDdhkPublicKey))
        require(peer.certDh.contentEquals(header.senderCertDh))

        val storedPrekey = database.getSignedPrekey(localEpoch, header.recipientSpkId)
            ?: throw IllegalStateException("The recipient signed prekey is not available locally.")
        val sessionId = metadata.envelopeId.copyOf()
        val localMessageId = UUID.randomUUID().toString()
        return identityStore.withStorageKey { storageKey ->
            val prekey = crypto.restoreSignedPrekeyContext(
                storedPrekey.rawSignedPrekey,
                storedPrekey.encryptedPrivateRecord,
                storageKey,
            )
            try {
                val native = crypto.acceptPrekeyMessage(
                    prekey = prekey,
                    sessionId = sessionId,
                    localEpoch = localEpoch,
                    envelopeWire = wire,
                    storageKey = storageKey,
                )
                try {
                    val initialSnapshot = native.currentSnapshot()
                    var plaintext: ByteArray? = null
                    var encryptedBody: ByteArray? = null
                    var pendingSnapshot: ByteArray? = null
                    try {
                        plaintext = native.stageDecryptMessage(wire)
                        encryptedBody = native.sealLocalMessageBody(1L, requireNotNull(plaintext))
                        pendingSnapshot = native.pendingSnapshot()
                        val now = System.currentTimeMillis()
                        val initialSession = StoredMessagingSession(
                            sessionId = sessionId.copyOf(),
                            peerAccountId = peer.accountId.copyOf(),
                            peerDeviceId = peer.deviceId.copyOf(),
                            localEpoch = localEpoch,
                            peerEpoch = peer.epoch,
                            generation = 0L,
                            encryptedSnapshot = initialSnapshot,
                            firstPrekeyHeader = ByteArray(0),
                            createdAtMillis = now,
                            updatedAtMillis = now,
                        )
                        val draft = EncryptedMessageDraft(
                            localMessageId = localMessageId,
                            sessionId = sessionId.copyOf(),
                            protocolEnvelopeId = metadata.envelopeId.copyOf(),
                            direction = StoredMessageDirection.INBOUND,
                            generation = 1L,
                            encryptedBody = requireNotNull(encryptedBody),
                            envelopeWire = wire.copyOf(),
                            createdAtMillis = now,
                        )
                        val result = try {
                            database.commitInitialIncomingTransition(
                                initialSession = initialSession,
                                gatewayEnvelopeId = fetched.envelopeId,
                                message = draft,
                                pendingEncryptedSnapshot = requireNotNull(pendingSnapshot),
                            )
                        } catch (failure: Throwable) {
                            runCatching { native.discardStaged() }.onFailure(failure::addSuppressed)
                            throw failure
                        }
                        if (result == IncomingCommitResult.INSERTED) native.commitStaged()
                        else native.discardStaged()
                        result
                    } finally {
                        initialSnapshot.fill(0)
                        plaintext?.fill(0)
                        encryptedBody?.fill(0)
                        pendingSnapshot?.fill(0)
                    }
                } finally {
                    native.close()
                }
            } finally {
                prekey.close()
            }
        }.also { sessionId.fill(0) }
    }

    /**
     * Established MessageEnvelopeV1 does not carry a session ID. A peer device can
     * therefore have multiple independent ratchet sessions. Try every eligible,
     * trusted persisted session against an isolated restored native handle. Native
     * AEAD authentication identifies the session that owns the envelope.
     *
     * Nothing is persisted until exactly one candidate authenticates. Failed
     * candidates are closed without changing their durable ratchet snapshots.
     */
    private fun commitEstablishedSessionMessage(
        metadata: MessageEnvelopeMetadataV1,
        fetched: FetchedDeviceMessage,
        wire: ByteArray,
        peerTrust: InboundPeerTrustVerifier,
    ): IncomingCommitResult {
        data class AuthenticatedCandidate(
            val session: StoredMessagingSession,
            val native: NativeMessagingSessionHandle,
            val nextGeneration: Long,
            val encryptedBody: ByteArray,
            val pendingSnapshot: ByteArray,
        )

        val candidateSessions = database.getSessionsForPeerDevice(metadata.senderDeviceId)
            .filter { it.localEpoch == localEpoch }
        if (candidateSessions.isEmpty()) {
            throw IllegalStateException(
                "No established session exists for this sender device and local epoch."
            )
        }

        val authenticated = ArrayList<AuthenticatedCandidate>()
        val candidateFailures = ArrayList<String>()

        try {
            for (storedSession in candidateSessions) {
                require(storedSession.peerDeviceId.contentEquals(metadata.senderDeviceId)) {
                    "Persisted session is associated with a different sender device."
                }

                val peer = peerTrust.verifyExistingSession(storedSession)
                require(peer.accountId.contentEquals(storedSession.peerAccountId))
                require(peer.deviceId.contentEquals(metadata.senderDeviceId))
                require(peer.epoch == storedSession.peerEpoch)

                val native = identityStore.withStorageKey { storageKey ->
                    crypto.restoreMessagingSession(
                        peerAccountId = storedSession.peerAccountId,
                        peerDeviceId = storedSession.peerDeviceId,
                        localEpoch = storedSession.localEpoch,
                        peerEpoch = storedSession.peerEpoch,
                        sessionId = storedSession.sessionId,
                        generation = storedSession.generation,
                        encryptedSnapshot = storedSession.encryptedSnapshot,
                        firstPrekeyHeader = storedSession.firstPrekeyHeader,
                        storageKey = storageKey,
                    )
                }

                var plaintext: ByteArray? = null
                var encryptedBody: ByteArray? = null
                var pendingSnapshot: ByteArray? = null
                var transferred = false

                try {
                    plaintext = try {
                        native.stageDecryptMessage(wire)
                    } catch (failure: Exception) {
                        // stageDecryptMessage() stages only after Rust authenticates the
                        // envelope. The Rust transition helper operates on an isolated
                        // candidate, so an authentication failure leaves durable state intact.
                        candidateFailures.add(
                            "candidate-${candidateFailures.size + 1}:${failure.javaClass.simpleName}"
                        )
                        null
                    }

                    if (plaintext == null) {
                        continue
                    }

                    val nextGeneration = Math.addExact(storedSession.generation, 1L)
                    encryptedBody = native.sealLocalMessageBody(
                        nextGeneration,
                        requireNotNull(plaintext),
                    )
                    pendingSnapshot = native.pendingSnapshot()

                    authenticated.add(
                        AuthenticatedCandidate(
                            session = storedSession,
                            native = native,
                            nextGeneration = nextGeneration,
                            encryptedBody = requireNotNull(encryptedBody),
                            pendingSnapshot = requireNotNull(pendingSnapshot),
                        )
                    )
                    transferred = true
                } finally {
                    plaintext?.fill(0)
                    if (!transferred) {
                        encryptedBody?.fill(0)
                        pendingSnapshot?.fill(0)
                        native.close()
                    }
                }
            }

            if (authenticated.isEmpty()) {
                throw IllegalStateException(
                    "No persisted ratchet session authenticated this inbound envelope. " +
                        "Candidates=${candidateSessions.size}; failures=${candidateFailures.joinToString(",")}"
                )
            }
            if (authenticated.size != 1) {
                throw IllegalStateException(
                    "Multiple persisted ratchet sessions authenticated this inbound envelope " +
                        "(${authenticated.size}); refusing an ambiguous commit."
                )
            }

            val match = authenticated.single()
            val localMessageId = UUID.randomUUID().toString()
            val now = System.currentTimeMillis()
            val draft = EncryptedMessageDraft(
                localMessageId = localMessageId,
                sessionId = match.session.sessionId.copyOf(),
                protocolEnvelopeId = metadata.envelopeId.copyOf(),
                direction = StoredMessageDirection.INBOUND,
                generation = match.nextGeneration,
                encryptedBody = match.encryptedBody,
                envelopeWire = wire.copyOf(),
                createdAtMillis = now,
            )

            val result = database.commitIncomingTransition(
                expectedGeneration = match.session.generation,
                gatewayEnvelopeId = fetched.envelopeId,
                message = draft,
                pendingEncryptedSnapshot = match.pendingSnapshot,
            )

            if (result == IncomingCommitResult.INSERTED) {
                // SQLite has committed the authenticated message, ACK receipt and
                // encrypted snapshot before native state promotion.
                match.native.commitStaged()
            } else {
                match.native.discardStaged()
            }
            return result
        } finally {
            for (candidate in authenticated) {
                runCatching { candidate.native.close() }
                candidate.encryptedBody.fill(0)
                candidate.pendingSnapshot.fill(0)
            }
        }
    }
    fun listMessages(sessionId: ByteArray, limit: Int = 100): List<StoredMessage> =
        database.listMessages(sessionId, limit)

    private fun validatePeer(peer: VerifiedPeerPrekeyMaterial) {
        require(peer.accountId.size == ID_BYTES) { "Peer account ID must be 16 bytes." }
        require(peer.deviceId.size == ID_BYTES) { "Peer device ID must be 16 bytes." }
        require(peer.dskPublicKey.size == PUBLIC_KEY_BYTES) { "Peer DSK must be 32 bytes." }
        require(peer.ddhkPublicKey.size == PUBLIC_KEY_BYTES) { "Peer DDHK must be 32 bytes." }
        require(peer.rawSignedPrekey.isNotEmpty() && peer.rawSignedPrekey.size <= MAX_SIGNED_PREKEY_BYTES) {
            "Peer signed-prekey object has an invalid size."
        }
        require(peer.epoch in 1L..MAX_U32) { "Peer epoch is outside the protocol u32 range." }
        require(!peer.accountId.contentEquals(localIdentity.accountId) ||
            !peer.deviceId.contentEquals(localIdentity.deviceId)) {
            "Cannot create a peer session with this same device."
        }
    }

    private fun randomId(): ByteArray {
        var candidate: ByteArray
        do {
            candidate = ByteArray(ID_BYTES).also(random::nextBytes)
        } while (candidate.all { it == 0.toByte() })
        return candidate
    }

    private fun uuidFromBytes(bytes: ByteArray): String {
        require(bytes.size == ID_BYTES) { "Device ID must be 16 bytes." }
        val hex = bytes.joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 0xFF) }
        return buildString(36) {
            append(hex.substring(0, 8)); append('-')
            append(hex.substring(8, 12)); append('-')
            append(hex.substring(12, 16)); append('-')
            append(hex.substring(16, 20)); append('-')
            append(hex.substring(20, 32))
        }
    }

    private fun safeErrorCode(error: Exception): String {
        val raw = (error as? DeviceMessageHttpException)?.errorCode
            ?: error.javaClass.simpleName.ifBlank { "NETWORK_ERROR" }
        return raw.uppercase(Locale.ROOT)
            .replace(Regex("[^A-Z0-9_]"), "_")
            .take(MAX_ERROR_CODE_LENGTH)
            .ifBlank { "NETWORK_ERROR" }
    }

    private companion object {
        const val ID_BYTES = 16
        const val PUBLIC_KEY_BYTES = 32
        const val MAX_U32 = 4_294_967_295L
        const val MAX_PLAINTEXT_BYTES = 60 * 1024
        const val MAX_SIGNED_PREKEY_BYTES = 4 * 1024
        const val MAX_ERROR_CODE_LENGTH = 64
        val random = SecureRandom()
    }
}
