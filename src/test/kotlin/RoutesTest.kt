package de.trustylynx

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

private const val TEST_TOKEN = "test-vault-token"
private val TEST_KEY = "ef2aaabcd310f69808a4283bea9b2b21c12ff90b14893b200f85d3b84e1eb4a6"
    .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
private const val TEST_C1 =
    "AQGElC3c4+PdZNooknZHuCveKBxC6pGXVPRxFb4lPO02949d7a5MrDAmYHiv4c7QGpYb5PtXMFFQqMW/L8M="

private class FakeKeyProvider : KeyProvider {
    val requestedVersions = mutableListOf<Int?>()

    override suspend fun derive(userId: String, version: Int?): DerivedKey {
        requestedVersions += version
        return DerivedKey(TEST_KEY.copyOf(), version ?: 1)
    }
}

private fun routeTest(block: suspend RouteTestEnv.() -> Unit) = testApplication {
    environment { config = MapApplicationConfig() }
    val keys = FakeKeyProvider()
    application {
        configureApp(
            AppConfig(TEST_TOKEN, "test-aes-token", null),
            keys,
        )
    }
    RouteTestEnv(client, keys).block()
}

private class RouteTestEnv(
    private val client: io.ktor.client.HttpClient,
    val keys: FakeKeyProvider,
) {
    suspend fun post(path: String, token: String? = TEST_TOKEN, body: String): io.ktor.client.statement.HttpResponse =
        client.post(path) {
            if (token != null) header(SERVICE_TOKEN_HEADER, token)
            contentType(ContentType.Application.Json)
            setBody(body)
        }

    suspend fun get(path: String) = client.get(path)

    suspend fun jsonField(response: io.ktor.client.statement.HttpResponse, name: String): String =
        Json.parseToJsonElement(response.bodyAsText()).jsonObject.getValue(name).jsonPrimitive.content
}

class RoutesTest {
    @Test
    fun `health endpoint does not require a token`() = routeTest {
        val response = get("/health")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("ok", jsonField(response, "status"))
    }

    @Test
    fun `encrypt and decrypt preserve the client ciphertext`() = routeTest {
        val body = """{"userId":"u42","itemId":"i7","part":"s","c1":"$TEST_C1"}"""
        val encrypted = post("/internal/encrypt", body = body)
        assertEquals(HttpStatusCode.OK, encrypted.status)
        val c2 = jsonField(encrypted, "c2")
        assertNotEquals(TEST_C1, c2)

        val decrypted = post(
            "/internal/decrypt",
            body = """{"userId":"u42","itemId":"i7","part":"s","c2":"$c2"}""",
        )
        assertEquals(HttpStatusCode.OK, decrypted.status)
        assertEquals(TEST_C1, jsonField(decrypted, "c1"))
        assertEquals(listOf(null, 1), keys.requestedVersions)
    }

    @Test
    fun `wrong service token is unauthorized`() = routeTest {
        val response = post(
            "/internal/encrypt",
            token = "wrong-token",
            body = """{"userId":"u42","itemId":"i7","part":"s","c1":"$TEST_C1"}""",
        )
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("unauthorized", jsonField(response, "error"))
        assertEquals(emptyList(), keys.requestedVersions)
    }

    @Test
    fun `ChaCha package is rejected before requesting a key`() = routeTest {
        val chachaC2 = Base64.getEncoder().encodeToString(
            byteArrayOf(0x54, 0x4C, 0x58, 0x32, 0x02, 0x02, 0x00, 0x01) +
                ByteArray(12) + ByteArray(78),
        )
        val response = post(
            "/internal/decrypt",
            body = """{"userId":"u42","itemId":"i7","part":"s","c2":"$chachaC2"}""",
        )
        assertEquals(HttpStatusCode.Conflict, response.status)
        assertEquals("wrong_service", jsonField(response, "error"))
        assertEquals(emptyList(), keys.requestedVersions)
    }

    @Test
    fun `zero key version is rejected before requesting a key`() = routeTest {
        val invalidC2 = Base64.getEncoder().encodeToString(
            byteArrayOf(0x54, 0x4C, 0x58, 0x32, 0x02, 0x01, 0x00, 0x00) +
                ByteArray(12) + ByteArray(78),
        )
        val response = post(
            "/internal/decrypt",
            body = """{"userId":"u42","itemId":"i7","part":"s","c2":"$invalidC2"}""",
        )
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("bad_request", jsonField(response, "error"))
        assertEquals(emptyList(), keys.requestedVersions)
    }

    @Test
    fun `tampered ciphertext returns integrity error`() = routeTest {
        val c2 = Base64.getDecoder().decode(
            "VExYMgIBAAHXZpAF8a91fTDcVLBKvMN9+2A/f4nQFrNv1uwEPEqKZSvmEOW+/6sxdWKU0CufByhv0YvQkXKX3Hcd9y7hZdGJ7vdC8YyMh+1gOAXEcPhe8DR8gsnXmH1qJsg=",
        )
        c2[c2.lastIndex] = (c2.last().toInt() xor 1).toByte()
        val encoded = Base64.getEncoder().encodeToString(c2)
        val response = post(
            "/internal/decrypt",
            body = """{"userId":"u42","itemId":"i7","part":"s","c2":"$encoded"}""",
        )
        assertEquals(HttpStatusCode.InternalServerError, response.status)
        assertEquals("integrity_error", jsonField(response, "error"))
    }

    @Test
    fun `invalid part is rejected`() = routeTest {
        val response = post(
            "/internal/encrypt",
            body = """{"userId":"u42","itemId":"i7","part":"x","c1":"$TEST_C1"}""",
        )
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("bad_request", jsonField(response, "error"))
        assertEquals(emptyList(), keys.requestedVersions)
    }
}
