package org.sovereign.pm.bootstrap

import org.sovereign.pm.crypto.NativeInitialAccountBootstrapSession

class InitialAccountBootstrapCoordinator(private val api: InitialAccountBootstrapApi) {
    fun register(session: NativeInitialAccountBootstrapSession, recoveryMnemonic: String) {
        val authorization = session.signAuthorization(recoveryMnemonic)
        var challenge: InitialBootstrapChallenge? = null
        var proof: ByteArray? = null
        try {
            challenge = api.requestChallenge(authorization.enrollmentCertificate, authorization.recoveryPublicKey)
            proof = session.signProofOfPossession(authorization.enrollmentCertificate, challenge.id, challenge.nonce)
            // Do not make client time authoritative; server validates expiry and exact challenge state.
            api.activate(authorization.enrollmentCertificate, proof, authorization.recoveryPublicKey)
        } finally {
            authorization.enrollmentCertificate.fill(0)
            authorization.recoveryPublicKey.fill(0)
            challenge?.id?.fill(0); challenge?.nonce?.fill(0)
            proof?.fill(0)
        }
    }
}
