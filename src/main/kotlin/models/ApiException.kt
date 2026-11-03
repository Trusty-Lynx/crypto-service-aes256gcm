package de.trustylynx.models

import io.ktor.http.HttpStatusCode

const val INTERNAL_ERROR = "internal_error"

// the two false turn off the stack trace, these errors are expected and never logged
open class ApiException(
    val status: HttpStatusCode,
    val code: String,
) : RuntimeException(code, null, false, false)

class BadRequest : ApiException(HttpStatusCode.BadRequest, "bad_request")

class Unauthorized : ApiException(HttpStatusCode.Unauthorized, "unauthorized")

class WrongService : ApiException(HttpStatusCode.Conflict, "wrong_service")

class PayloadTooLarge : ApiException(HttpStatusCode.PayloadTooLarge, "payload_too_large")

class IntegrityError : ApiException(HttpStatusCode.InternalServerError, "integrity_error")

class KeyServiceException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
