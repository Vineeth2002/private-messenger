package org.sovereign.pm.crypto

import org.sovereign.pm.crypto.uniffi.MessagingSession
import org.sovereign.pm.crypto.uniffi.SignedPrekeyContext

/**
 * Narrow, synchronized owner for the UniFFI messaging-session handle.
 * A staged transition is discarded on close unless the caller explicitly commits it.
 */
internal class NativeMessagingSessionHandle internal constructor(
    private val delegate: MessagingSession,
) : AutoCloseable {
    private val lock = Any()
    private var closed = false
    private var staged = false

    fun sessionId(): ByteArray = synchronized(lock) {
        checkOpen()
        delegate.sessionId().copyOf()
    }

    fun initialPrekeyHeader(): ByteArray = synchronized(lock) {
        checkOpen()
        check(!staged) { "Cannot read the initial header during a staged transition." }
        delegate.initialPrekeyHeader().copyOf()
    }

    fun currentSnapshot(): ByteArray = synchronized(lock) {
        checkOpen()
        check(!staged) { "Use pendingSnapshot while a transition is staged." }
        delegate.currentSnapshot().copyOf()
    }

    fun stageEncryptMessage(envelopeId: ByteArray, plaintext: ByteArray): ByteArray = synchronized(lock) {
        checkOpen()
        check(!staged) { "A messaging transition is already staged." }
        require(envelopeId.size == FIXED_ID_BYTES) { "Protocol envelope ID must be 16 bytes." }
        require(plaintext.isNotEmpty()) { "Message plaintext must not be empty." }
        val idCopy = envelopeId.copyOf()
        val plaintextCopy = plaintext.copyOf()
        try {
            val encrypted = delegate.stageEncryptMessage(idCopy, plaintextCopy)
            try {
                encrypted.copyOf().also { staged = true }
            } finally {
                encrypted.fill(0)
            }
        } finally {
            idCopy.fill(0)
            plaintextCopy.fill(0)
        }
    }

    fun stageDecryptMessage(envelopeWire: ByteArray): ByteArray = synchronized(lock) {
        checkOpen()
        check(!staged) { "A messaging transition is already staged." }
        require(envelopeWire.isNotEmpty()) { "Message envelope must not be empty." }
        val wireCopy = envelopeWire.copyOf()
        try {
            val plaintext = delegate.stageDecryptMessage(wireCopy)
            try {
                plaintext.copyOf().also { staged = true }
            } finally {
                plaintext.fill(0)
            }
        } finally {
            wireCopy.fill(0)
        }
    }

    /** Encrypts a local message-body copy under the session's StorageRecordCipher. */
    fun sealLocalMessageBody(generation: Long, plaintext: ByteArray): ByteArray = synchronized(lock) {
        checkOpen()
        check(staged) { "A message body can be sealed only for a staged transition." }
        require(generation > 0L) { "Message generation must be positive." }
        val plaintextCopy = plaintext.copyOf()
        try {
            val sealed = delegate.sealLocalMessageBody(generation.toULong(), plaintextCopy)
            try {
                sealed.copyOf()
            } finally {
                sealed.fill(0)
            }
        } finally {
            plaintextCopy.fill(0)
        }
    }

    /** Decrypts one stored body. Callers must zero the returned plaintext after use. */
    fun openLocalMessageBody(generation: Long, sealedBody: ByteArray): ByteArray = synchronized(lock) {
        checkOpen()
        require(generation > 0L) { "Message generation must be positive." }
        val sealedCopy = sealedBody.copyOf()
        try {
            val plaintext = delegate.openLocalMessageBody(generation.toULong(), sealedCopy)
            try {
                plaintext.copyOf()
            } finally {
                plaintext.fill(0)
            }
        } finally {
            sealedCopy.fill(0)
        }
    }

    fun pendingSnapshot(): ByteArray = synchronized(lock) {
        checkOpen()
        check(staged) { "No messaging transition is staged." }
        delegate.pendingSnapshot().copyOf()
    }

    fun commitStaged() = synchronized(lock) {
        checkOpen()
        check(staged) { "No messaging transition is staged." }
        delegate.commitStaged()
        staged = false
    }

    fun discardStaged() = synchronized(lock) {
        checkOpen()
        if (staged) {
            delegate.discardStaged()
            staged = false
        }
    }

    override fun close() {
        synchronized(lock) {
            if (closed) return
            try {
                if (staged) delegate.discardStaged()
            } finally {
                staged = false
                closed = true
                delegate.close()
            }
        }
    }

    private fun checkOpen() {
        check(!closed) { "Native messaging session is closed." }
    }

    private companion object {
        const val FIXED_ID_BYTES = 16
    }
}

/** Opaque local signed-prekey handle. Private key material never enters Kotlin. */
internal class NativeSignedPrekeyHandle internal constructor(
    private val delegate: SignedPrekeyContext,
) : AutoCloseable {
    private val lock = Any()
    private var closed = false

    fun rawSignedPrekey(): ByteArray = synchronized(lock) {
        check(!closed) { "Native signed-prekey handle is closed." }
        delegate.rawSignedPrekey().copyOf()
    }

    fun sealForStorage(storageKey: ByteArray): ByteArray = synchronized(lock) {
        check(!closed) { "Native signed-prekey handle is closed." }
        require(storageKey.size == STORAGE_KEY_BYTES) { "Storage DEK must be 32 bytes." }
        val keyCopy = storageKey.copyOf()
        try {
            val sealed = delegate.sealForStorage(keyCopy)
            try {
                sealed.copyOf()
            } finally {
                sealed.fill(0)
            }
        } finally {
            keyCopy.fill(0)
        }
    }

    internal fun nativeHandle(): SignedPrekeyContext = synchronized(lock) {
        check(!closed) { "Native signed-prekey handle is closed." }
        delegate
    }

    override fun close() {
        synchronized(lock) {
            if (!closed) {
                closed = true
                delegate.close()
            }
        }
    }

    private companion object {
        const val STORAGE_KEY_BYTES = 32
    }
}
