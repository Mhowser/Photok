/*
 *   Copyright 2020-2023 Leon Latsch
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package dev.leonlatsch.photok.security.encryption

import dev.leonlatsch.photok.other.AES
import dev.leonlatsch.photok.other.SHA_256
import timber.log.Timber
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject

private const val PASSWORD_MIN_LENGTH = 6

class EncryptionManagerV2 @Inject constructor(
    private val cipherFactory: CipherFactory
): EncryptionManager {

    private var encryptionKey: SecretKeySpec? = null

    override var isReady: Boolean = false

    override fun initialize(password: String) {
        if (password.length < PASSWORD_MIN_LENGTH) {
            isReady = false
            return
        }

        try {
            encryptionKey = generateKeySpec(password)
            isReady = true
        } catch (e: GeneralSecurityException) {
            Timber.d("Error initializing EncryptionManager: $e")
            isReady = false
        }
    }

    override fun reset() {
        encryptionKey = null
        isReady = false
    }

    override fun createCipher(mode: Int): Cipher? = createCipher(mode, encryptionKey)

    private fun createCipher(mode: Int, secretKeySpec: SecretKeySpec?): Cipher? {
        return if (isReady) {
            cipherFactory.create(mode, secretKeySpec)
        } else {
            Timber.d("EncryptionManager has to be ready to create a cipher")
            null
        }
    }

    private fun createCipher(mode: Int, password: String): Cipher? {
        val keySpec = generateKeySpec(password)
        return createCipher(mode, keySpec)
    }

    override fun createCipherInputStream(
        origInputStream: InputStream,
        password: String?
    ): CipherInputStream? = if (isReady) try {
        val cipher = if (password == null) {
            createCipher(Cipher.DECRYPT_MODE)
        } else {
            createCipher(Cipher.DECRYPT_MODE, password)
        }

        CipherInputStream(origInputStream, cipher)
    } catch (e: GeneralSecurityException) {
        Timber.e("Error creating encrypted input stream: $e")
        null
    } else {
        Timber.e("Cannot create encrypted input stream if key is not ready")
        null
    }

    override fun createCipherOutputStream(
        origOutputStream: OutputStream,
        password: String?
    ): CipherOutputStream? = if (isReady) try {
        val cipher = if (password == null) {
            createCipher(Cipher.ENCRYPT_MODE)
        } else {
            createCipher(Cipher.ENCRYPT_MODE, password)
        }

        CipherOutputStream(origOutputStream, cipher)
    } catch (e: GeneralSecurityException) {
        Timber.e("Error creating encrypted input stream: $e")
        null
    } else {
        Timber.e("Cannot create encrypted input stream if key is not ready")
        null
    }

    private fun generateKeySpec(password: String): SecretKeySpec =
        MessageDigest.getInstance(SHA_256).let { md ->
            val bytes = md.digest(password.toByteArray(StandardCharsets.UTF_8))
            SecretKeySpec(bytes, AES)
        }
}