package de.trustylynx.services

import de.trustylynx.clients.KeyProvider
import de.trustylynx.models.BadRequest
import de.trustylynx.models.DecryptResponse
import de.trustylynx.models.EncryptResponse
import de.trustylynx.models.IntegrityError
import de.trustylynx.models.KeyServiceException
import de.trustylynx.models.WrongService
import de.trustylynx.security.InvalidPackage
import de.trustylynx.security.Target
import de.trustylynx.security.Tlx2
import de.trustylynx.security.WrongCryptoService
import de.trustylynx.security.toBase64
import kotlinx.coroutines.CancellationException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException

class CryptoService(private val keys: KeyProvider) {
    private val random = SecureRandom()

    suspend fun encrypt(target: Target, c1: ByteArray): EncryptResponse {
        val nonce = ByteArray(Tlx2.NONCE_LENGTH)
        random.nextBytes(nonce)

        val c2 = withKey(target.userId, version = null) { key, version ->
            Tlx2.seal(key, version, nonce, c1, target)
        }
        return EncryptResponse(c2.toBase64())
    }

    suspend fun decrypt(target: Target, c2: ByteArray): DecryptResponse {
        val keyVersion = try {
            Tlx2.keyVersionOf(c2)
        } catch (_: WrongCryptoService) {
            throw WrongService()
        } catch (_: InvalidPackage) {
            throw BadRequest()
        }

        val c1 = withKey(target.userId, keyVersion) { key, _ ->
            try {
                Tlx2.open(key, c2, target)
            } catch (_: AEADBadTagException) {
                throw IntegrityError()
            } catch (_: InvalidPackage) {
                throw BadRequest()
            }
        }
        return DecryptResponse(c1.toBase64())
    }

    private suspend fun withKey(
        userId: String,
        version: Int?,
        block: (key: ByteArray, version: Int) -> ByteArray,
    ): ByteArray {
        val derived = try {
            keys.derive(userId, version)
        } catch (e: CancellationException) {
            throw e // request got cancelled, not the key service's fault
        } catch (e: Exception) {
            throw KeyServiceException("key-service derive failed", e)
        }
        try {
            if (derived.key.size != Tlx2.KEY_LENGTH ||
                derived.version !in 1..Tlx2.MAX_KEY_VERSION ||
                (version != null && derived.version != version)
            ) {
                throw KeyServiceException("key-service derive returned an unusable key")
            }
            return block(derived.key, derived.version)
        } finally {
            derived.key.fill(0) // don't leave the key in memory
        }
    }
}
