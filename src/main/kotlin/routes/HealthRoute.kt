package de.trustylynx.routes

import de.trustylynx.models.HealthResponse
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get

fun Route.healthRoute() {
    get("/health") {
        call.respond(HealthResponse("ok"))
    }
}
