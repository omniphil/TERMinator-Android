package com.syncterm.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages encryption/decryption of SSH credentials using Android Keystore.
 * Uses AES-256-GCM for secure storage of passwords.
 */
class CredentialManager(private val context: Context) {

    companion object {
        private const val TAG = "CredentialManager"
        private const val KEYSTORE_ALIAS = "TERMinator_SSH_Key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 128
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    /**
     * Encrypt a password for secure storage.
     * @param password The plaintext password to encrypt
     * @return Base64 encoded string containing IV + encrypted data, or null on failure
     */
    fun encryptPassword(password: String): String? {
        if (password.isEmpty()) {
            return null
        }

        return try {
            val secretKey = getOrCreateSecretKey()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val iv = cipher.iv
            val encryptedBytes = cipher.doFinal(password.toByteArray(Charsets.UTF_8))

            // Combine IV and encrypted data
            val combined = ByteArray(iv.size + encryptedBytes.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)

            Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to encrypt password: ${e.message}", e)
            null
        }
    }

    /**
     * Decrypt a previously encrypted password.
     * @param encryptedPassword Base64 encoded string from encryptPassword()
     * @return The decrypted plaintext password, or null on failure
     */
    fun decryptPassword(encryptedPassword: String?): String? {
        if (encryptedPassword.isNullOrEmpty()) {
            return null
        }

        return try {
            val combined = Base64.decode(encryptedPassword, Base64.NO_WRAP)

            // Validate minimum size: IV (12 bytes) + at least 1 byte encrypted + GCM tag (16 bytes)
            val minSize = GCM_IV_LENGTH + 1 + (GCM_TAG_LENGTH / 8)
            if (combined.size < minSize) {
                Log.e(TAG, "Encrypted data too short: ${combined.size} bytes, need at least $minSize")
                return null
            }

            val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
            // Validate IV size explicitly
            if (iv.size != GCM_IV_LENGTH) {
                Log.e(TAG, "Invalid IV size: ${iv.size}, expected $GCM_IV_LENGTH")
                return null
            }
            val encryptedBytes = combined.copyOfRange(GCM_IV_LENGTH, combined.size)

            val secretKey = getSecretKey()
            if (secretKey == null) {
                Log.e(TAG, "Secret key not found")
                return null
            }

            val cipher = Cipher.getInstance(TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

            val decryptedBytes = cipher.doFinal(encryptedBytes)
            String(decryptedBytes, Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt password: ${e.message}", e)
            null
        }
    }

    /**
     * Check if a password is encrypted (vs plaintext).
     * Encrypted passwords are Base64 encoded and have a minimum length.
     */
    fun isEncrypted(password: String?): Boolean {
        if (password.isNullOrEmpty()) return false
        return try {
            val decoded = Base64.decode(password, Base64.NO_WRAP)
            // Must have at least IV + 1 byte of encrypted data
            decoded.size > GCM_IV_LENGTH
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get existing secret key from keystore.
     */
    private fun getSecretKey(): SecretKey? {
        return try {
            val entry = keyStore.getEntry(KEYSTORE_ALIAS, null) as? KeyStore.SecretKeyEntry
            entry?.secretKey
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get secret key: ${e.message}", e)
            null
        }
    }

    /**
     * Get existing key or create a new one if it doesn't exist.
     */
    private fun getOrCreateSecretKey(): SecretKey {
        val existingKey = getSecretKey()
        if (existingKey != null) {
            return existingKey
        }

        // Create new key
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val spec = KeyGenParameterSpec.Builder(
            KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }
}
