package org.sovereign.pm.crypto

import org.sovereign.pm.crypto.uniffi.AccountContext
import org.sovereign.pm.crypto.uniffi.decodeStrictCanonical as nativeDecodeStrictCanonical
import org.sovereign.pm.crypto.uniffi.identityInitialize
import org.sovereign.pm.crypto.uniffi.identityRestore
import org.sovereign.pm.crypto.uniffi.recoveryMnemonicGenerate
import org.sovereign.pm.crypto.uniffi.verifySignedPrekeyForPeerV1

class UniFfiCryptoBridge : CryptoBridge {
    private companion object {
        const val ID_BYTES: Int = 16
        const val PUBLIC_KEY_BYTES: Int = 32
        const val STORAGE_KEY_BYTES: Int = 32
        const val MAX_U32: Long = 4_294_967_295L
    }
    private var accountHandle: AccountContext? = null

    override fun decodeStrictCanonical(bytes: ByteArray): ByteArray =
        nativeDecodeStrictCanonical(bytes)

    /** Native strict-CBOR, DSK-signature and account/device/epoch binding check for alpha pairing. */
    internal fun verifySignedPrekeyForPairing(
        rawSignedPrekey: ByteArray,
        dskPublicKey: ByteArray,
        accountId: ByteArray,
        epoch: Long,
        deviceId: ByteArray,
    ): ByteArray {
        require(dskPublicKey.size == PUBLIC_KEY_BYTES)
        require(accountId.size == ID_BYTES && deviceId.size == ID_BYTES)
        require(epoch in 1L..MAX_U32)
        val rawCopy = rawSignedPrekey.copyOf()
        val dskCopy = dskPublicKey.copyOf()
        val accountCopy = accountId.copyOf()
        val deviceCopy = deviceId.copyOf()
        try {
            return verifySignedPrekeyForPeerV1(
                rawCopy, dskCopy, accountCopy, epoch.toULong(), deviceCopy,
            ).also { verified ->
                require(verified.contentEquals(rawSignedPrekey)) {
                    "Native pairing verifier returned different signed-prekey bytes."
                }
            }
        } finally {
            rawCopy.fill(0)
            dskCopy.fill(0)
            accountCopy.fill(0)
            deviceCopy.fill(0)
        }
    }

    override fun generateRecoveryMnemonic(): String = recoveryMnemonicGenerate()

    @Synchronized
    override fun initializeAccount(): AccountIdentity {
        val handle = identityInitialize()
        val identity = handle.toPublicIdentity()
        val previous = accountHandle
        accountHandle = handle
        previous?.close()
        return identity
    }

    @Synchronized
    override fun sealCurrentAccount(storageKey: ByteArray): ByteArray {
        val handle = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        return handle.sealForStorage(storageKey)
    }

    @Synchronized
    override fun restoreAccount(record: ByteArray, storageKey: ByteArray): AccountIdentity {
        val handle = identityRestore(record, storageKey)
        val identity = handle.toPublicIdentity()
        val previous = accountHandle
        accountHandle = handle
        previous?.close()
        return identity
    }

    /**
     * Clone the selected native context and bind it to the supplied public identity. The clone
     * remains valid if this bridge later restores or initializes another account.
     */
    @Synchronized
    override fun bindDeviceRequestSigner(identity: AccountIdentity): DeviceRequestSigner {
        val current = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        val currentIdentity = current.toPublicIdentity()
        val matches = currentIdentity.accountId.contentEquals(identity.accountId) &&
            currentIdentity.deviceId.contentEquals(identity.deviceId) &&
            currentIdentity.dskPublicKey.contentEquals(identity.dskPublicKey) &&
            currentIdentity.ddhkPublicKey.contentEquals(identity.ddhkPublicKey)
        require(matches) { "Requested signer identity does not match the active native account." }

        val boundHandle = AccountContext(current.uniffiClonePointer())
        return object : DeviceRequestSigner {
            private val lock = Any()
            private var closed = false

            override fun signDeviceHttpRequestV1(
                epoch: ULong,
                method: String,
                requestTarget: String,
                body: ByteArray,
            ): ByteArray = synchronized(lock) {
                check(!closed) { "Device request signer is closed." }
                boundHandle.signDeviceHttpRequestV1(epoch, method, requestTarget, body)
            }

            override fun close() = synchronized(lock) {
                if (!closed) {
                    closed = true
                    boundHandle.close()
                }
            }
        }
    }

    /**
     * Bind first-account authorization to the exact active identity already held by this bridge.
     * This clones the existing native context; it does not generate a replacement account/device.
     */
    @Synchronized
    fun beginInitialAccountBootstrap(identity: AccountIdentity): NativeInitialAccountBootstrapSession {
        val current = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        val currentIdentity = current.toPublicIdentity()
        val matches = currentIdentity.accountId.contentEquals(identity.accountId) &&
            currentIdentity.deviceId.contentEquals(identity.deviceId) &&
            currentIdentity.dskPublicKey.contentEquals(identity.dskPublicKey) &&
            currentIdentity.ddhkPublicKey.contentEquals(identity.ddhkPublicKey)
        require(matches) { "Requested bootstrap identity does not match the active native account." }

        val boundHandle = AccountContext(current.uniffiClonePointer())
        return NativeInitialAccountBootstrapSession(boundHandle)
    }
    /**
     * Starts a separate in-memory enrollment context for a new device under an existing account.
     * It does not replace the bridge's current account handle or activate the new device.
     */
    fun beginAdditionalDeviceEnrollment(existingAccountId: ByteArray): NativeDeviceEnrollmentSession =
        NativeDeviceEnrollmentSession.create(existingAccountId)

    /** Restore a separately persisted enrollment-device context without changing the current account. */
    fun restoreAdditionalDeviceEnrollment(record: ByteArray, storageKey: ByteArray): NativeDeviceEnrollmentSession =
        NativeDeviceEnrollmentSession.restore(record, storageKey)

    @Synchronized
    internal fun activeAccountIdentity(): AccountIdentity {
        val current = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        return current.toPublicIdentity()
    }

    /**
     * Signs the canonical transparency leaf with the active native account's device signing key.
     * Cert_dh, the signed-prekey public key and PushPK must be generated/validated by their
     * authoritative native components before they are passed here. This method never substitutes
     * the recovery enrollment certificate for Cert_dh and never generates placeholder key bytes.
     */
    @Synchronized
    internal fun signTransparencyLeaf(
        epoch: Long,
        certDh: ByteArray,
        signedPrekeyPublicKey: ByteArray,
        pushPublicKey: ByteArray,
    ): ByteArray {
        require(epoch in 1L..MAX_U32) { "Account epoch is outside the protocol u32 range." }
        require(certDh.size == 64) { "Cert_dh must be exactly 64 bytes." }
        require(signedPrekeyPublicKey.size == PUBLIC_KEY_BYTES) {
            "Signed-prekey public key must be exactly 32 bytes."
        }
        require(pushPublicKey.size == PUBLIC_KEY_BYTES) {
            "Push public key must be exactly 32 bytes."
        }

        val current = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        val certDhCopy = certDh.copyOf()
        val signedPrekeyCopy = signedPrekeyPublicKey.copyOf()
        val pushPublicKeyCopy = pushPublicKey.copyOf()
        try {
            return current.signTransparencyLeaf(
                epoch.toULong(),
                certDhCopy,
                signedPrekeyCopy,
                pushPublicKeyCopy,
            )
        } finally {
            certDhCopy.fill(0)
            signedPrekeyCopy.fill(0)
            pushPublicKeyCopy.fill(0)
        }
    }
    /** Generates a local signed-prekey handle in the currently restored native account. */
    @Synchronized
    internal fun generateSignedPrekeyContext(epoch: Long, signedPrekeyId: Long): NativeSignedPrekeyHandle {
        require(epoch in 1L..MAX_U32) { "Account epoch is outside the protocol u32 range." }
        require(signedPrekeyId in 1L..MAX_U32) { "Signed-prekey ID is outside the protocol u32 range." }
        val current = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        val native = current.generateSignedPrekey(epoch.toULong(), signedPrekeyId.toUInt())
        return NativeSignedPrekeyHandle(native)
    }

    /** Restores the local signed-prekey private context from its encrypted SQLite record. */
    @Synchronized
    internal fun restoreSignedPrekeyContext(
        rawSignedPrekey: ByteArray,
        encryptedPrivateRecord: ByteArray,
        storageKey: ByteArray,
    ): NativeSignedPrekeyHandle {
        require(rawSignedPrekey.isNotEmpty()) { "Signed-prekey public object is empty." }
        require(encryptedPrivateRecord.isNotEmpty()) { "Encrypted signed-prekey record is empty." }
        require(storageKey.size == STORAGE_KEY_BYTES) { "Storage DEK must be 32 bytes." }
        val current = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        val rawCopy = rawSignedPrekey.copyOf()
        val recordCopy = encryptedPrivateRecord.copyOf()
        val keyCopy = storageKey.copyOf()
        try {
            return NativeSignedPrekeyHandle(current.restoreSignedPrekey(rawCopy, recordCopy, keyCopy))
        } finally {
            rawCopy.fill(0)
            recordCopy.fill(0)
            keyCopy.fill(0)
        }
    }

    /**
     * Creates an initiator session from peer keys supplied by the messaging trust layer.
     * This method does not independently verify peer enrollment, revocation, transparency or
     * directory anti-rollback evidence; those checks must happen before this call.
     */
    @Synchronized
    internal fun createInitiatorMessagingSession(
        peerAccountId: ByteArray,
        peerDeviceId: ByteArray,
        peerEpoch: Long,
        peerDskPublic: ByteArray,
        peerDdhkPublic: ByteArray,
        peerSignedPrekey: ByteArray,
        sessionId: ByteArray,
        localEpoch: Long,
        storageKey: ByteArray,
    ): NativeMessagingSessionHandle {
        require(peerAccountId.size == ID_BYTES && peerDeviceId.size == ID_BYTES) {
            "Peer account and device IDs must be 16 bytes."
        }
        require(peerDskPublic.size == PUBLIC_KEY_BYTES && peerDdhkPublic.size == PUBLIC_KEY_BYTES) {
            "Peer public keys must be 32 bytes."
        }
        require(sessionId.size == ID_BYTES) { "Session ID must be 16 bytes." }
        require(peerEpoch in 1L..MAX_U32 && localEpoch in 1L..MAX_U32) {
            "Account epoch is outside the protocol u32 range."
        }
        require(storageKey.size == STORAGE_KEY_BYTES) { "Storage DEK must be 32 bytes." }
        val current = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        val peerAccountCopy = peerAccountId.copyOf()
        val peerDeviceCopy = peerDeviceId.copyOf()
        val peerDskCopy = peerDskPublic.copyOf()
        val peerDdhkCopy = peerDdhkPublic.copyOf()
        val signedPrekeyCopy = peerSignedPrekey.copyOf()
        val sessionCopy = sessionId.copyOf()
        val keyCopy = storageKey.copyOf()
        try {
            val native = current.createInitiatorSession(
                peerAccountCopy,
                peerDeviceCopy,
                peerEpoch.toULong(),
                peerDskCopy,
                peerDdhkCopy,
                signedPrekeyCopy,
                sessionCopy,
                localEpoch.toULong(),
                keyCopy,
            )
            return NativeMessagingSessionHandle(native)
        } finally {
            peerAccountCopy.fill(0)
            peerDeviceCopy.fill(0)
            peerDskCopy.fill(0)
            peerDdhkCopy.fill(0)
            signedPrekeyCopy.fill(0)
            sessionCopy.fill(0)
            keyCopy.fill(0)
        }
    }

    /** Restores a persisted native session; the DEK is copied only for this synchronous FFI call. */
    @Synchronized
    internal fun restoreMessagingSession(
        peerAccountId: ByteArray,
        peerDeviceId: ByteArray,
        localEpoch: Long,
        peerEpoch: Long,
        sessionId: ByteArray,
        generation: Long,
        encryptedSnapshot: ByteArray,
        firstPrekeyHeader: ByteArray,
        storageKey: ByteArray,
    ): NativeMessagingSessionHandle {
        require(peerAccountId.size == ID_BYTES && peerDeviceId.size == ID_BYTES) {
            "Peer account and device IDs must be 16 bytes."
        }
        require(sessionId.size == ID_BYTES) { "Session ID must be 16 bytes." }
        require(localEpoch in 1L..MAX_U32 && peerEpoch in 1L..MAX_U32) {
            "Account epoch is outside the protocol u32 range."
        }
        require(generation >= 0L) { "Session generation cannot be negative." }
        require(encryptedSnapshot.isNotEmpty()) { "Encrypted ratchet snapshot is empty." }
        require(storageKey.size == STORAGE_KEY_BYTES) { "Storage DEK must be 32 bytes." }
        val current = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        val accountCopy = peerAccountId.copyOf()
        val deviceCopy = peerDeviceId.copyOf()
        val sessionCopy = sessionId.copyOf()
        val snapshotCopy = encryptedSnapshot.copyOf()
        val headerCopy = firstPrekeyHeader.copyOf()
        val keyCopy = storageKey.copyOf()
        try {
            val native = current.restoreMessagingSession(
                accountCopy,
                deviceCopy,
                localEpoch.toULong(),
                peerEpoch.toULong(),
                sessionCopy,
                generation.toULong(),
                snapshotCopy,
                headerCopy,
                keyCopy,
            )
            return NativeMessagingSessionHandle(native)
        } finally {
            accountCopy.fill(0)
            deviceCopy.fill(0)
            sessionCopy.fill(0)
            snapshotCopy.fill(0)
            headerCopy.fill(0)
            keyCopy.fill(0)
        }
    }

    /** Accepts a first prekey message using the local native signed-prekey context. */
    @Synchronized
    internal fun acceptPrekeyMessage(
        prekey: NativeSignedPrekeyHandle,
        sessionId: ByteArray,
        localEpoch: Long,
        envelopeWire: ByteArray,
        storageKey: ByteArray,
    ): NativeMessagingSessionHandle {
        require(sessionId.size == ID_BYTES) { "Session ID must be 16 bytes." }
        require(localEpoch in 1L..MAX_U32) { "Local epoch is outside the protocol u32 range." }
        require(envelopeWire.isNotEmpty()) { "Prekey message envelope is empty." }
        require(storageKey.size == STORAGE_KEY_BYTES) { "Storage DEK must be 32 bytes." }
        val current = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        val sessionCopy = sessionId.copyOf()
        val envelopeCopy = envelopeWire.copyOf()
        val keyCopy = storageKey.copyOf()
        try {
            val native = current.acceptPrekeyMessage(
                prekey.nativeHandle(),
                sessionCopy,
                localEpoch.toULong(),
                envelopeCopy,
                keyCopy,
            )
            return NativeMessagingSessionHandle(native)
        } finally {
            sessionCopy.fill(0)
            envelopeCopy.fill(0)
            keyCopy.fill(0)
        }
    }

    private fun AccountContext.toPublicIdentity() = AccountIdentity(
        accountId = accountId(),
        deviceId = deviceId(),
        dskPublicKey = dskPublicKey(),
        ddhkPublicKey = ddhkPublicKey(),
    )
}
