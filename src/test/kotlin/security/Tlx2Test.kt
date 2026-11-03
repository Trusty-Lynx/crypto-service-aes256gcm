package de.trustylynx.security

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

private fun String.hexBytes(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private fun String.base64Bytes(): ByteArray = Base64.getDecoder().decode(this)

class Tlx2Test {
    private val target = Target("u42", "i7", Part.SECRET)
    private val key = "ef2aaabcd310f69808a4283bea9b2b21c12ff90b14893b200f85d3b84e1eb4a6".hexBytes()
    private val nonce = "d7669005f1af757d30dc54b0".hexBytes()
    private val c1 =
        "AQGElC3c4+PdZNooknZHuCveKBxC6pGXVPRxFb4lPO02949d7a5MrDAmYHiv4c7QGpYb5PtXMFFQqMW/L8M=".base64Bytes()
    private val c2 =
        "VExYMgIBAAHXZpAF8a91fTDcVLBKvMN9+2A/f4nQFrNv1uwEPEqKZSvmEOW+/6sxdWKU0CufByhv0YvQkXKX3Hcd9y7hZdGJ7vdC8YyMh+1gOAXEcPhe8DR8gsnXmH1qJsg=".base64Bytes()

    @Test
    fun `AES seal matches the documented test vector`() {
        assertContentEquals(c2, Tlx2.seal(key, 1, nonce, c1, target))
    }

    @Test
    fun `AES open restores the original C1`() {
        assertContentEquals(c1, Tlx2.open(key, c2, target))
    }

    @Test
    fun `AES package is 36 bytes longer than C1`() {
        assertEquals(c1.size + 36, c2.size)
    }

    @Test
    fun `ChaCha package is identified as belonging to another service`() {
        val chachaHeader = byteArrayOf(0x54, 0x4C, 0x58, 0x32, 0x02, 0x02, 0x00, 0x01)
        assertFailsWith<WrongCryptoService> { Tlx2.keyVersionOf(chachaHeader) }
    }

    @Test
    fun `zero key version is an invalid package`() {
        val invalidHeader = byteArrayOf(0x54, 0x4C, 0x58, 0x32, 0x02, 0x01, 0x00, 0x00)
        assertFailsWith<InvalidPackage> { Tlx2.keyVersionOf(invalidHeader) }
    }
}
