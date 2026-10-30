package de.trustylynx

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

class DerivedKey(val key: ByteArray, val version: Int) {
    override fun toString(): String = "DerivedKey(version=$version)"
}

interface KeyProvider {
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
            throw e
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

    private companion object {
        const val DEV_KEY_BASE64 = "7yqqvNMQ9pgIpCg76psrIcEv+QsUiTsgD4XTuE4etKY="
    }
}

fun createKeyServiceHttpClient(): HttpClient = HttpClient(CIO) {
    expectSuccess = false
    install(ContentNegotiation) {
        json(Json { ignoreUnknownKeys = true; explicitNulls = false })
    }
    install(HttpTimeout) {
        connectTimeoutMillis = 2_000
        requestTimeoutMillis = 10_000
    }
}

@Serializable
private data class DeriveRequest(val userId: String, val alg: String, val version: Int?)

@Serializable
private data class DeriveResponse(val key: String, val version: Int) {
    override fun toString(): String = "DeriveResponse(version=$version)"
}

const val SERVICE_TOKEN_HEADER = "X-Service-Token"

internal fun String.decodeBase64OrNull(): ByteArray? {
    if (length % 4 != 0) return null
    return try {
        Base64.getDecoder().decode(this)
    } catch (_: IllegalArgumentException) {
        null
    }
}

internal fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)
