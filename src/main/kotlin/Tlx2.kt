package de.trustylynx

import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

enum class Part(val wire: String) {
    HEAD("h"),
    SECRET("s"),
    DEK("dek"),
}

data class Target(val userId: String, val itemId: String?, val part: Part)

class InvalidPackage : RuntimeException()

class WrongCryptoService : RuntimeException()

/**
 * TLX2 format for the AES-GCM backend encryption layer.
 * C2 = header || nonce || AES-256-GCM ciphertext and tag.
 */
object Tlx2 {
    const val KEY_LENGTH = 32
    const val NONCE_LENGTH = 12
    const val TAG_LENGTH = 16
    const val MAX_KEY_VERSION = 0xFFFF

    private val MAGIC = byteArrayOf(0x54, 0x4C, 0x58, 0x32)
    private const val FORMAT_VERSION: Byte = 0x02
    private const val ALG_AES: Byte = 0x01
    private const val ALG_CHACHA: Byte = 0x02
    private const val HEADER_LENGTH = 8
    private const val PAYLOAD_OFFSET = HEADER_LENGTH + NONCE_LENGTH
    private const val C1_OVERHEAD = 30
    private const val MIN_PADDING_BLOCK = 32
    private const val MAX_PADDING_BLOCK = 65_536
    private const val WDEK_LENGTH = 62

    const val MIN_C2_LENGTH = WDEK_LENGTH + HEADER_LENGTH + NONCE_LENGTH + TAG_LENGTH
    const val MAX_C2_LENGTH = MAX_PADDING_BLOCK + C1_OVERHEAD + HEADER_LENGTH + NONCE_LENGTH + TAG_LENGTH

    fun isValidC1(c1: ByteArray, part: Part): Boolean {
        if (c1.size < 2 || c1[0] != 0x01.toByte() || c1[1] != 0x01.toByte()) return false
        if (part == Part.DEK) return c1.size == WDEK_LENGTH
        val paddingBlock = c1.size - C1_OVERHEAD
        return paddingBlock in MIN_PADDING_BLOCK..MAX_PADDING_BLOCK &&
            (paddingBlock and (paddingBlock - 1)) == 0
    }

    fun seal(key: ByteArray, keyVersion: Int, nonce: ByteArray, c1: ByteArray, target: Target): ByteArray {
        require(key.size == KEY_LENGTH)
        require(keyVersion in 1..MAX_KEY_VERSION)
        require(nonce.size == NONCE_LENGTH)
        require(isValidC1(c1, target.part))

        val header = MAGIC + byteArrayOf(
            FORMAT_VERSION,
            ALG_AES,
            (keyVersion shr 8).toByte(),
            keyVersion.toByte(),
        )
        val cipher = cipher(Cipher.ENCRYPT_MODE, key, nonce, header, target)
        return header + nonce + cipher.doFinal(c1)
    }

    fun open(key: ByteArray, c2: ByteArray, target: Target): ByteArray {
        if (key.size != KEY_LENGTH || c2.size !in MIN_C2_LENGTH..MAX_C2_LENGTH) {
            throw InvalidPackage()
        }

        val keyVersion = keyVersionOf(c2)
        if (keyVersion !in 1..MAX_KEY_VERSION) throw InvalidPackage()

        val header = c2.copyOfRange(0, HEADER_LENGTH)
        val nonce = c2.copyOfRange(HEADER_LENGTH, PAYLOAD_OFFSET)
        val cipher = cipher(Cipher.DECRYPT_MODE, key, nonce, header, target)
        val c1 = cipher.doFinal(c2, PAYLOAD_OFFSET, c2.size - PAYLOAD_OFFSET)
        if (!isValidC1(c1, target.part)) throw InvalidPackage()
        return c1
    }

    fun keyVersionOf(c2: ByteArray): Int {
        if (c2.size < HEADER_LENGTH ||
            !c2.copyOfRange(0, MAGIC.size).contentEquals(MAGIC) ||
            c2[4] != FORMAT_VERSION
        ) {
            throw InvalidPackage()
        }

        when (c2[5]) {
            ALG_AES -> Unit
            ALG_CHACHA -> throw WrongCryptoService()
            else -> throw InvalidPackage()
        }

        val keyVersion = ((c2[6].toInt() and 0xFF) shl 8) or (c2[7].toInt() and 0xFF)
        if (keyVersion == 0) throw InvalidPackage()
        return keyVersion
    }

    private fun cipher(mode: Int, key: ByteArray, nonce: ByteArray, header: ByteArray, target: Target): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_LENGTH * 8, nonce))
            updateAAD(aad(header, target))
        }

    private fun aad(header: ByteArray, target: Target): ByteArray {
        val context = when (target.part) {
            Part.DEK -> "|${target.userId}|dek"
            else -> "|${target.userId}|${target.itemId}|${target.part.wire}"
        }
        return header + context.toByteArray(StandardCharsets.UTF_8)
    }
}
