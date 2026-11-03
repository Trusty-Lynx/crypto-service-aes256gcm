package de.trustylynx.clients

import de.trustylynx.SERVICE_TOKEN_HEADER
import de.trustylynx.models.KeyServiceException
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.util.Base64

// test vector key from the docs, only used in development mode
private const val DEV_KEY_BASE64 = "7yqqvNMQ9pgIpCg76psrIcEv+QsUiTsgD4XTuE4etKY="

class DerivedKey(val key: ByteArray, val version: Int)

interface KeyProvider {
    // version null means the current key
    suspend fun derive(userId: String, version: Int?): DerivedKey
}

class HttpKeyProvider(
    private val http: HttpClient,
    baseUrl: String,
    private val serviceToken: String,
) : KeyProvider {
    private val url = baseUrl.trimEnd('/') + "/internal/keys/derive"

    override suspend fun derive(userId: String, version: Int?): DerivedKey {
        val response = try {
            http.post(url) {
                header(SERVICE_TOKEN_HEADER, serviceToken)
                contentType(ContentType.Application.Json)
                setBody(DeriveRequest(userId = userId, alg = "aes", version = version))
            }
        } catch (e: CancellationException) {
            throw e // request got cancelled, not the key service's fault
        } catch (e: Exception) {
            throw KeyServiceException("key-service derive failed", e)
        }

        if (response.status != HttpStatusCode.OK) {
            throw KeyServiceException("key-service derive answered ${response.status.value}")
        }

        val body = try {
            response.body<DeriveResponse>()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw KeyServiceException("key-service derive returned an invalid response", e)
        }
        val key = try {
            Base64.getDecoder().decode(body.key)
        } catch (e: IllegalArgumentException) {
            throw KeyServiceException("key-service derive returned invalid Base64", e)
        }
        return DerivedKey(key, body.version)
    }
}

class DevKeyProvider : KeyProvider {
    override suspend fun derive(userId: String, version: Int?): DerivedKey {
        if (version != null && version != 1) throw KeyServiceException("dev key version is unavailable")
        return DerivedKey(Base64.getDecoder().decode(DEV_KEY_BASE64), 1)
    }
}

fun createKeyServiceHttpClient(): HttpClient = HttpClient(CIO) {
    expectSuccess = false
    install(ContentNegotiation) {
        // explicitNulls = false leaves version out of the request when it's null
        json(Json { ignoreUnknownKeys = true; explicitNulls = false })
    }
    install(HttpTimeout) {
        connectTimeoutMillis = 2_000
        requestTimeoutMillis = 10_000
    }
}

@Serializable
private data class DeriveRequest(val userId: String, val alg: String, val version: Int?)

// toString leaves out the key, so it can't end up in a log
@Serializable
private data class DeriveResponse(val key: String, val version: Int) {
    override fun toString(): String = "DeriveResponse(version=$version)"
}
