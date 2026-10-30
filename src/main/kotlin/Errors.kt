package de.trustylynx

import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.application.log
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respond
import kotlinx.serialization.Serializable

sealed class ApiException(
    val status: HttpStatusCode,
    val code: String,
) : RuntimeException(code, null, false, false)

class BadRequest : ApiException(HttpStatusCode.BadRequest, "bad_request")
class Unauthorized : ApiException(HttpStatusCode.Unauthorized, "unauthorized")
class WrongService : ApiException(HttpStatusCode.Conflict, "wrong_service")
class PayloadTooLarge : ApiException(HttpStatusCode.PayloadTooLarge, "payload_too_large")
class IntegrityError : ApiException(HttpStatusCode.InternalServerError, "integrity_error")
class KeyServiceException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

const val INTERNAL_ERROR = "internal_error"

@Serializable
data class ErrorResponse(val error: String)

fun Application.configureStatusPages() {
    install(StatusPages) {
        exception<ApiException> { call, cause ->
            call.respond(cause.status, ErrorResponse(cause.code))
        }
        exception<Throwable> { call, cause ->
            call.application.log.error(
                "Unhandled error on ${call.request.httpMethod.value} ${call.request.path()}",
                cause,
            )
            call.respond(HttpStatusCode.InternalServerError, ErrorResponse(INTERNAL_ERROR))
        }
    }
}
