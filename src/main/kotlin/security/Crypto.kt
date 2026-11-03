package de.trustylynx.security

import java.util.Base64

fun String.decodeBase64OrNull(): ByteArray? {
    if (length % 4 != 0) return null
    return try {
        Base64.getDecoder().decode(this)
    } catch (_: IllegalArgumentException) {
        null
    }
}

fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)
