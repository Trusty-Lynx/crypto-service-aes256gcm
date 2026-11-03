package de.trustylynx.routes

import de.trustylynx.models.BadRequest
import de.trustylynx.security.Part
import de.trustylynx.security.Target
import de.trustylynx.security.Tlx2
import de.trustylynx.security.decodeBase64OrNull

// no | allowed, otherwise an id could change the meaning of the AAD
private val ID_PATTERN = Regex("[A-Za-z0-9._-]{1,128}")

fun validateTarget(userId: String, itemId: String?, part: String): Target {
    val parsedPart = Part.entries.firstOrNull { it.wire == part } ?: throw BadRequest()
    val validItemId = if (parsedPart == Part.DEK) itemId == null else itemId != null && ID_PATTERN.matches(itemId)
    if (!ID_PATTERN.matches(userId) || !validItemId) throw BadRequest()
    return Target(userId, itemId, parsedPart)
}

fun validateC1(value: String, part: Part): ByteArray {
    val c1 = value.decodeBase64OrNull()
    if (c1 == null || !Tlx2.isValidC1(c1, part)) throw BadRequest()
    return c1
}

fun validateC2(value: String): ByteArray {
    val c2 = value.decodeBase64OrNull()
    if (c2 == null || c2.size !in Tlx2.MIN_C2_LENGTH..Tlx2.MAX_C2_LENGTH) throw BadRequest()
    return c2
}

// these values come straight from the request, only valid ids may end up in the log
fun forLog(value: String?): String {
    if (value == null || !ID_PATTERN.matches(value)) return "-"
    return value
}
