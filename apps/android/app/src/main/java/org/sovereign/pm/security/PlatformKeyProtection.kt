package org.sovereign.pm.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/** PPAL Level 2: Rust encrypts identity material; Android Keystore wraps only its local Storage DEK. */
enum class Ppal {
    LEVEL_1_HARDWARE_ISOLATED,
    LEVEL_2_WRAPPED_AT_REST,
}

enum class KekBacking {
    STRONGBOX,
    TEE,
    HARDWARE_UNSPECIFIED,
    SOFTWARE,
}

data class KekCapabilities(
    val backing: KekBacking,
    val achievedPpal: Ppal,
)

interface PlatformKek {
    /** Reports whether the wrapping-key alias already exists; must not create a key. */
    fun hasExistingKey(): Boolean

    /** Describes the backing of an existing wrapping key; must not create a key. */
    fun discover(): KekCapabilities

    /** Wraps exactly the transient 32-byte local Storage DEK, never a protocol private key. */
    fun wrap(plaintextBlob: ByteArray): ByteArray

    /** Unwraps the DEK only when the previously provisioned Android Keystore key still exists. */
    fun unwrap(wrappedBlob: ByteArray): ByteArray
}

/** Android Keystore implementation for the local-storage DEK only. */
class AndroidKeystorePlatformKek internal constructor(
    private val context: Context,
    // Internal injection permits integration tests to isolate their key from production data.
    private val keyAlias: String = KEY_ALIAS,
) : PlatformKek {

    private val lock = Any()

    override fun hasExistingKey(): Boolean = synchronized(lock) {
        loadKeyStore().containsAlias(keyAlias)
    }

    override fun discover(): KekCapabilities = synchronized(lock) {
        val key = getExistingKey()
            ?: throw IllegalStateException("Storage protection key is unavailable.")

        val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
        val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo

        val backing = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KekBacking.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KekBacking.TEE
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> KekBacking.SOFTWARE
                else -> KekBacking.HARDWARE_UNSPECIFIED
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) {
                // Older Android versions do not reliably distinguish TEE from StrongBox.
                KekBacking.HARDWARE_UNSPECIFIED
            } else {
                KekBacking.SOFTWARE
            }
        }

        KekCapabilities(
            backing = backing,
            achievedPpal = Ppal.LEVEL_2_WRAPPED_AT_REST,
        )
    }

    override fun wrap(plaintextBlob: ByteArray): ByteArray = synchronized(lock) {
        require(plaintextBlob.size == DEK_BYTES) {
            "Storage DEK must be 32 bytes."
        }

        val key = getOrCreateKey()
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(WRAP_AAD)

        val ciphertextAndTag = cipher.doFinal(plaintextBlob)
        val iv = cipher.iv

        if (iv.size != GCM_IV_BYTES ||
            ciphertextAndTag.size != DEK_BYTES + GCM_TAG_BYTES
        ) {
            throw IllegalStateException("Unexpected Android Keystore wrapping output.")
        }

        iv + ciphertextAndTag
    }

    override fun unwrap(wrappedBlob: ByteArray): ByteArray = synchronized(lock) {
        if (wrappedBlob.size != WRAPPED_DEK_BYTES) {
            throw IllegalStateException("Stored key wrapper is malformed.")
        }

        // Never generate a replacement wrapping key during restore.
        val key = getExistingKey()
            ?: throw IllegalStateException(
                "Storage protection key is missing; refusing identity replacement."
            )

        val iv = wrappedBlob.copyOfRange(0, GCM_IV_BYTES)
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            GCMParameterSpec(GCM_TAG_BITS, iv),
        )
        cipher.updateAAD(WRAP_AAD)

        val plaintext = cipher.doFinal(
            wrappedBlob,
            GCM_IV_BYTES,
            wrappedBlob.size - GCM_IV_BYTES,
        )

        if (plaintext.size != DEK_BYTES) {
            plaintext.fill(0)
            throw IllegalStateException("Unwrapped storage key has an invalid size.")
        }

        plaintext
    }

    private fun getOrCreateKey(): SecretKey {
        getExistingKey()?.let { return it }

        val hasStrongBox =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.packageManager.hasSystemFeature(
                    PackageManager.FEATURE_STRONGBOX_KEYSTORE
                )

        if (hasStrongBox) {
            try {
                return generateKey(preferStrongBox = true)
            } catch (_: StrongBoxUnavailableException) {
                // Retry without requiring StrongBox.
            }
        }

        return generateKey(preferStrongBox = false)
    }

    private fun generateKey(preferStrongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)

        if (preferStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE,
        )
        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun getExistingKey(): SecretKey? {
        val keyStore = loadKeyStore()
        if (!keyStore.containsAlias(keyAlias)) return null

        return keyStore.getKey(keyAlias, null) as? SecretKey
            ?: throw IllegalStateException("Storage protection key is invalid.")
    }

    private fun loadKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "org.sovereign.pm.identity-storage-dek.v1"
        const val AES_GCM = "AES/GCM/NoPadding"
        const val DEK_BYTES = 32
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128
        const val GCM_TAG_BYTES = 16
        const val WRAPPED_DEK_BYTES = GCM_IV_BYTES + DEK_BYTES + GCM_TAG_BYTES

        val WRAP_AAD =
            "SOVEREIGN-PM-STORAGE-DEK-WRAP-v1".toByteArray(Charsets.US_ASCII)
    }
}
