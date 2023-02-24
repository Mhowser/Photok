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

import java.io.InputStream
import java.io.OutputStream
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream

class EncryptionManagerV2 : EncryptionManager {

    override fun initialize(password: String) {
        TODO("Not yet implemented")
    }

    override fun reset() {
        TODO("Not yet implemented")
    }

    override fun createCipher(mode: Int): Cipher? {
        TODO("Not yet implemented")
    }

    override fun createCipherInputStream(
        origInputStream: InputStream,
        password: String?
    ): CipherInputStream? {
        TODO("Not yet implemented")
    }

    override fun createCipherOutputStream(
        origOutputStream: OutputStream,
        password: String?
    ): CipherOutputStream? {
        TODO("Not yet implemented")
    }
}