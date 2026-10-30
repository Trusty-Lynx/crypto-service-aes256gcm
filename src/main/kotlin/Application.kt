package de.trustylynx

import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopped
import io.ktor.server.application.install
import io.ktor.server.application.log
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.netty.EngineMain

fun main(args: Array<String>) {
    EngineMain.main(args)
}

fun Application.module() {
    val config = AppConfig.fromEnv()
    val keys = when {
        config.keyServiceUrl != null -> {
            val http = createKeyServiceHttpClient()
            monitor.subscribe(ApplicationStopped) { http.close() }
            HttpKeyProvider(http, config.keyServiceUrl, config.aesServiceToken)
        }
        developmentMode -> {
            log.warn("KEY_SERVICE_URL is empty: using the dev stub key for every user")
            DevKeyProvider()
        }
        else -> error("Missing required environment variable KEY_SERVICE_URL (only optional in development mode)")
    }

    configureApp(config, keys)
}

fun Application.configureApp(config: AppConfig, keys: KeyProvider) {
    install(ContentNegotiation) { json() }
    configureStatusPages()
    routing {
        cryptoRoutes(config, keys)
    }
}
