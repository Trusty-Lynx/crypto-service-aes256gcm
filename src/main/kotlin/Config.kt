package de.trustylynx

class AppConfig(
    val vaultServiceToken: String,
    val aesServiceToken: String,
    val keyServiceUrl: String?,
) {
    override fun toString(): String = "AppConfig(keyServiceUrl=$keyServiceUrl)"

    companion object {
        fun fromEnv() = AppConfig(
            vaultServiceToken = env("VAULT_SERVICE_TOKEN"),
            aesServiceToken = env("AES_SERVICE_TOKEN"),
            keyServiceUrl = System.getenv("KEY_SERVICE_URL")?.takeIf { it.isNotBlank() },
        )

        private fun env(name: String): String =
            System.getenv(name)?.takeIf { it.isNotBlank() }
                ?: error("Missing required environment variable $name")
    }
}
