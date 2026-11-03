package de.trustylynx.plugins

import de.trustylynx.models.ApiException
import de.trustylynx.models.ErrorResponse
import de.trustylynx.models.INTERNAL_ERROR
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.application.log
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respond

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
