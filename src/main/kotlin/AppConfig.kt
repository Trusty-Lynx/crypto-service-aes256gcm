package de.trustylynx

const val SERVICE_TOKEN_HEADER = "X-Service-Token"

class AppConfig(
    val vaultServiceToken: String,
    val aesServiceToken: String,
    // can only be missing in development mode, module() uses the dev key then
    val keyServiceUrl: String?,
) {
    companion object {
        fun fromEnv() = AppConfig(
            vaultServiceToken = requiredEnv("VAULT_SERVICE_TOKEN"),
            aesServiceToken = requiredEnv("AES_SERVICE_TOKEN"),
            keyServiceUrl = optionalEnv("KEY_SERVICE_URL"),
        )
    }
}

private fun requiredEnv(name: String): String =
    optionalEnv(name) ?: error("Missing required environment variable $name")

private fun optionalEnv(name: String): String? {
    val value = System.getenv(name)
    return if (value.isNullOrBlank()) null else value
}
