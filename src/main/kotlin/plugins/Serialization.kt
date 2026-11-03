package de.trustylynx.plugins

import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation

fun Application.configureSerialization() {
    // only for responses, request bodies are parsed with requestJson in CryptoRoutes
    install(ContentNegotiation) { json() }
}
