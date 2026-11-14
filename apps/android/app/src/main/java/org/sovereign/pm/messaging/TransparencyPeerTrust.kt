package org.sovereign.pm.messaging

import java.io.IOException

internal data class VerifiedPeerIdentity(
    val accountId: ByteArray,
    val deviceId: ByteArray,
    val epoch: Long,
    val dskPublicKey: ByteArray,
    val ddhkPublicKey: ByteArray,
    val certDh: ByteArray,
    val trustState: TransparencyTrustState,
)

internal interface InboundPeerTrustVerifier {
    fun verifyFirstContact(metadata: MessageEnvelopeMetadataV1, header: PrekeyHandshakeMetadataV1): VerifiedPeerIdentity
    fun verifyExistingSession(session: StoredMessagingSession): VerifiedPeerIdentity
}

/**
 * Binds first-contact header fields and established-session peer identity to a native-verified
 * current KT proof. A missing witness quorum is rejected unless the caller explicitly enables
 * degraded trust for a controlled alpha test. Cryptographic proof/signature/consistency failures
 * are always rejected by TransparencyV1Verifier.
 */
internal class TransparencyBackedPeerTrustVerifier(
    private val proofClient: TransparencyProofHttpClient,
    private val allowDegradedForControlledAlpha: Boolean = false,
) : InboundPeerTrustVerifier {
    override fun verifyFirstContact(
        metadata: MessageEnvelopeMetadataV1,
        header: PrekeyHandshakeMetadataV1,
    ): VerifiedPeerIdentity {
        val proof = proofClient.fetchVerifiedDeviceProof(header.senderAccountId, metadata.senderDeviceId)
        requireTrustState(proof.trustState)
        if (!proof.accountId.contentEquals(header.senderAccountId) ||
            !proof.deviceId.contentEquals(metadata.senderDeviceId) ||
            proof.epoch.toLong() != header.senderAccountEpoch ||
            !proof.dskPublicKey.contentEquals(header.senderDskPublicKey) ||
            !proof.ddhkPublicKey.contentEquals(header.senderDdhkPublicKey) ||
            !proof.certDh.contentEquals(header.senderCertDh)
        ) {
            throw IOException("Prekey handshake identity fields do not match the current verified KT leaf.")
        }
        return proof.toVerifiedPeer()
    }

    override fun verifyExistingSession(session: StoredMessagingSession): VerifiedPeerIdentity {
        val proof = proofClient.fetchVerifiedDeviceProof(session.peerAccountId, session.peerDeviceId)
        requireTrustState(proof.trustState)
        if (!proof.accountId.contentEquals(session.peerAccountId) ||
            !proof.deviceId.contentEquals(session.peerDeviceId) ||
            proof.epoch.toLong() != session.peerEpoch
        ) {
            throw IOException("Existing peer session no longer matches the current KT device state.")
        }
        return proof.toVerifiedPeer()
    }

    private fun requireTrustState(state: TransparencyTrustState) {
        if (state == TransparencyTrustState.DEGRADED && !allowDegradedForControlledAlpha) {
            throw IOException("Peer KT proof is cryptographically valid but lacks the configured 2-of-3 witness quorum.")
        }
    }

    private fun VerifiedKtDeviceProof.toVerifiedPeer() = VerifiedPeerIdentity(
        accountId = accountId.copyOf(),
        deviceId = deviceId.copyOf(),
        epoch = epoch.toLong(),
        dskPublicKey = dskPublicKey.copyOf(),
        ddhkPublicKey = ddhkPublicKey.copyOf(),
        certDh = certDh.copyOf(),
        trustState = trustState,
    )
}
