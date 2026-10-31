package org.sovereign.pm.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.sovereign.pm.crypto.uniffi.recoveryInitialize

/**
 * Exercises recovery phrase generation and validation through the real Android native library.
 * The generated phrase is never logged, included in assertion text, or persisted by this test.
 */
@RunWith(AndroidJUnit4::class)
class RecoveryMnemonicInstrumentedTest {

    @Test
    fun generatedPhraseIsValidTwentyFourWordEnglishBip39Mnemonic() {
        val mnemonic = UniFfiCryptoBridge().generateRecoveryMnemonic()
        val words = mnemonic.trim().split(Regex("\\s+"))

        assertEquals(
            "Generated recovery phrase must contain exactly 24 words",
            24,
            words.size
        )
        assertTrue(
            "Generated recovery phrase must not contain blank words",
            words.all { it.isNotBlank() }
        )

        // Native recovery initialization validates the English BIP-39 wordlist and checksum.
        val recoveryContext = recoveryInitialize(mnemonic)
        try {
            assertEquals(32, recoveryContext.recoveryPublicKey().size)
            assertEquals(32, recoveryContext.recoveryCommitment().size)
        } finally {
            recoveryContext.close()
        }
    }
}