package de.trustylynx.clients

import de.trustylynx.models.KeyServiceException
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

private const val KEY_BASE64 = "7yqqvNMQ9pgIpCg76psrIcEv+QsUiTsgD4XTuE4etKY="
private const val SERVICE_TOKEN = "test-aes-token"

private class ReceivedRequest(
    val method: String,
    val path: String,
    val token: String?,
    val contentType: String?,
    val body: String,
)

private class StubResponse(
    val status: HttpStatusCode = HttpStatusCode.OK,
    val body: String = """{"key":"$KEY_BASE64","version":1}""",
)

// a real server and the real http client, so this also covers the json settings of the client
private fun withStubKeyService(
    response: StubResponse = StubResponse(),
    baseUrlSuffix: String = "",
    block: suspend (keys: KeyProvider, received: List<ReceivedRequest>) -> Unit,
) = runBlocking {
    val received = CopyOnWriteArrayList<ReceivedRequest>()
    val server = embeddedServer(Netty, port = 0, host = "127.0.0.1") {
        routing {
            route("{path...}") {
                handle {
                    received += ReceivedRequest(
                        method = call.request.httpMethod.value,
                        path = call.request.path(),
                        token = call.request.headers["X-Service-Token"],
                        contentType = call.request.headers[HttpHeaders.ContentType],
                        body = call.receiveText(),
                    )
                    call.respondText(response.body, ContentType.Application.Json, response.status)
                }
            }
        }
    }.start(wait = false)
    val http = createKeyServiceHttpClient()
    try {
        val port = server.engine.resolvedConnectors().first().port
        block(HttpKeyProvider(http, "http://127.0.0.1:$port$baseUrlSuffix", SERVICE_TOKEN), received)
    } finally {
        http.close()
        server.stop(0, 0)
    }
}

class KeyProviderTest {
    private val key = Base64.getDecoder().decode(KEY_BASE64)

    @Test
    fun `derive without a version leaves the field out`() = withStubKeyService { keys, received ->
        val derived = keys.derive("u42", null)

        assertContentEquals(key, derived.key)
        assertEquals(1, derived.version)
        val request = received.single()
        assertEquals("POST", request.method)
        assertEquals("/internal/keys/derive", request.path)
        assertEquals(SERVICE_TOKEN, request.token)
        assertEquals("application/json", request.contentType)
        assertEquals("""{"userId":"u42","alg":"aes"}""", request.body)
    }

    @Test
    fun `derive with a version sends it`() = withStubKeyService { keys, received ->
        keys.derive("u42", 3)
        assertEquals("""{"userId":"u42","alg":"aes","version":3}""", received.single().body)
    }

    @Test
    fun `a slash at the end of the base url is ignored`() = withStubKeyService(baseUrlSuffix = "/") { keys, received ->
        keys.derive("u42", null)
        assertEquals("/internal/keys/derive", received.single().path)
    }

    @Test
    fun `unknown fields in the answer are ignored`() = withStubKeyService(
        StubResponse(body = """{"key":"$KEY_BASE64","version":2,"extra":true}"""),
    ) { keys, _ ->
        assertEquals(2, keys.derive("u42", null).version)
    }

    @Test
    fun `any status other than 200 fails`() {
        listOf(HttpStatusCode.Created, HttpStatusCode.NotFound, HttpStatusCode.InternalServerError).forEach { status ->
            withStubKeyService(StubResponse(status = status)) { keys, _ ->
                val failure = assertFailsWith<KeyServiceException> { keys.derive("u42", null) }
                assertEquals("key-service derive answered ${status.value}", failure.message)
            }
        }
    }

    @Test
    fun `an unreadable answer fails`() {
        listOf("not json", "{}", """{"key":"$KEY_BASE64"}""").forEach { body ->
            withStubKeyService(StubResponse(body = body)) { keys, _ ->
                val failure = assertFailsWith<KeyServiceException> { keys.derive("u42", null) }
                assertEquals("key-service derive returned an invalid response", failure.message)
            }
        }
    }

    @Test
    fun `invalid base64 in the answer fails`() = withStubKeyService(
        StubResponse(body = """{"key":"!!!!","version":1}"""),
    ) { keys, _ ->
        val failure = assertFailsWith<KeyServiceException> { keys.derive("u42", null) }
        assertEquals("key-service derive returned invalid Base64", failure.message)
    }

    @Test
    fun `an unreachable key service fails`() = runBlocking {
        val http = createKeyServiceHttpClient()
        try {
            val keys = HttpKeyProvider(http, "http://127.0.0.1:1", SERVICE_TOKEN)
            val failure = assertFailsWith<KeyServiceException> { keys.derive("u42", null) }
            assertEquals("key-service derive failed", failure.message)
        } finally {
            http.close()
        }
    }

    @Test
    fun `the dev provider only knows version 1`() = runBlocking {
        val keys = DevKeyProvider()

        listOf(null, 1).forEach { version ->
            val derived = keys.derive("anyone", version)
            assertContentEquals(key, derived.key)
            assertEquals(1, derived.version)
        }
        val failure = assertFailsWith<KeyServiceException> { keys.derive("anyone", 2) }
        assertEquals("dev key version is unavailable", failure.message)
    }
}
