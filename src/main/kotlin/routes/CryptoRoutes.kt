package de.trustylynx.routes

import de.trustylynx.SERVICE_TOKEN_HEADER
import de.trustylynx.models.ApiException
import de.trustylynx.models.BadRequest
import de.trustylynx.models.DecryptRequest
import de.trustylynx.models.EncryptRequest
import de.trustylynx.models.INTERNAL_ERROR
import de.trustylynx.models.PayloadTooLarge
import de.trustylynx.models.Unauthorized
import de.trustylynx.services.CryptoService
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import io.ktor.utils.io.readBuffer
import kotlinx.io.readByteArray
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.security.MessageDigest

private const val MAX_BODY_BYTES = 256 * 1024L

private val audit = LoggerFactory.getLogger("audit")
private val requestJson = Json { ignoreUnknownKeys = true }

fun Route.cryptoRoutes(crypto: CryptoService, vaultServiceToken: String) {
    val expectedToken = vaultServiceToken.encodeToByteArray()

    post("/internal/encrypt") {
        // check the token before the body, so a broken body without a token still gets a 401
        call.requireServiceToken(expectedToken)
        val request = call.receiveJson<EncryptRequest>()

        val target = validateTarget(request.userId, request.itemId, request.part)
        val c1 = validateC1(request.c1, target.part)
        call.respond(crypto.encrypt(target, c1))
    }

    post("/internal/decrypt") {
        // the try also covers the token check, every failed decrypt needs an audit line
        var request: DecryptRequest? = null
        val response = try {
            call.requireServiceToken(expectedToken)
            val parsed = call.receiveJson<DecryptRequest>()
            request = parsed

            val target = validateTarget(parsed.userId, parsed.itemId, parsed.part)
            val c2 = validateC2(parsed.c2)
            crypto.decrypt(target, c2)
        } catch (e: Exception) {
            audit.warn(
                "decrypt failed userId={} itemId={} part={} error={}",
                forLog(request?.userId),
                forLog(request?.itemId),
                forLog(request?.part),
                (e as? ApiException)?.code ?: INTERNAL_ERROR,
            )
            throw e
        }
        call.respond(response)
    }
}

private fun ApplicationCall.requireServiceToken(expected: ByteArray) {
    val provided = request.headers[SERVICE_TOKEN_HEADER]?.encodeToByteArray() ?: throw Unauthorized()
    // constant time, so the token can't be guessed byte by byte
    if (!MessageDigest.isEqual(expected, provided)) throw Unauthorized()
}

private suspend inline fun <reified T> ApplicationCall.receiveJson(): T {
    // read one byte more than allowed, that's how we notice a body that's too large
    val body = receiveChannel().readBuffer(MAX_BODY_BYTES + 1).readByteArray()
    if (body.size > MAX_BODY_BYTES) throw PayloadTooLarge()
    return try {
        requestJson.decodeFromString<T>(body.decodeToString())
    } catch (_: IllegalArgumentException) { // SerializationException is one of these
        throw BadRequest()
    }
}
