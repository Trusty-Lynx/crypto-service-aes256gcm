package de.trustylynx

import de.trustylynx.clients.DevKeyProvider
import de.trustylynx.clients.HttpKeyProvider
import de.trustylynx.clients.KeyProvider
import de.trustylynx.clients.createKeyServiceHttpClient
import de.trustylynx.plugins.configureSerialization
import de.trustylynx.plugins.configureStatusPages
import de.trustylynx.routes.cryptoRoutes
import de.trustylynx.routes.healthRoute
import de.trustylynx.services.CryptoService
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopped
import io.ktor.server.application.log
import io.ktor.server.netty.EngineMain
import io.ktor.server.routing.routing

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

// separate from module() so the tests can start the app with a fake key provider
fun Application.configureApp(config: AppConfig, keys: KeyProvider) {
    configureSerialization()
    configureStatusPages()
    routing {
        healthRoute()
        cryptoRoutes(CryptoService(keys), config.vaultServiceToken)
    }
}
