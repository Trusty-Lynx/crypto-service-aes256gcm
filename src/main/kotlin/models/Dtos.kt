package de.trustylynx.models

import kotlinx.serialization.Serializable

// the field names are the API, don't rename them
// toString leaves out c1 and c2, so they can't end up in a log

@Serializable
data class EncryptRequest(val userId: String, val itemId: String? = null, val part: String, val c1: String) {
    override fun toString(): String = "EncryptRequest(userId=$userId, itemId=$itemId, part=$part)"
}

@Serializable
data class EncryptResponse(val c2: String) {
    override fun toString(): String = "EncryptResponse"
}

@Serializable
data class DecryptRequest(val userId: String, val itemId: String? = null, val part: String, val c2: String) {
    override fun toString(): String = "DecryptRequest(userId=$userId, itemId=$itemId, part=$part)"
}

@Serializable
data class DecryptResponse(val c1: String) {
    override fun toString(): String = "DecryptResponse"
}

@Serializable
data class HealthResponse(val status: String)

@Serializable
data class ErrorResponse(val error: String)
