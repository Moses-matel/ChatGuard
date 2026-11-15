package id.chatguard.core.model

import android.content.Context
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.InputStream

@Serializable
enum class Verdict {
    AMAN,
    MENCURIGAKAN,
    BERBAHAYA
}

@Serializable
enum class FileType {
    APK,
    PDF,
    OFFICE,
    ARCHIVE,
    UNKNOWN
}

@Serializable
data class Signal(
    val code: String,
    val weight: Int,
    val detail: String
)

@Serializable
data class AnalysisReport(
    val fileName: String,
    val fileType: FileType,
    val sha256: String,
    val verdict: Verdict,
    val score: Int,
    val signals: List<Signal>,
    val extractedUrls: List<String>,
    val packageName: String? = null,
    val certSha256: String? = null
)

@Serializable
data class NotificationAlert(
    val sourcePackage: String,
    val sender: String,
    val fileName: String,
    val verdict: Verdict,
    val reasons: List<String>
)

@Serializable
data class ReputationResponse(
    val verdict: String,
    val threatCategory: String? = null,
    val officialCertMatch: Boolean? = null,
    val flaggedUrls: List<String> = emptyList()
)

@Serializable
data class VerdictFeedbackRequest(
    val sha256: String,
    val fileType: String,
    val packageName: String? = null,
    val certSha256: String? = null,
    val shownVerdict: String,
    val userNote: String? = null
)

@Serializable
data class OfficialAppEntry(
    val packageName: String,
    val appName: String,
    val certSha256: String,
    val category: String
)

object OfficialCertAllowlist {
    const val ASSET_NAME: String = "indonesian_official_certs.json"

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
    }

    fun load(context: Context): Map<String, OfficialAppEntry> {
        return try {
            context.assets.open(ASSET_NAME).use { stream ->
                loadFromStream(stream)
            }
        } catch (_: Exception) {
            emptyMap()
        }
    }

    fun loadFromStream(input: InputStream): Map<String, OfficialAppEntry> {
        return try {
            val content = input.bufferedReader().use { it.readText() }
            if (content.isBlank()) return emptyMap()
            val list = json.decodeFromString<List<OfficialAppEntry>>(content)
            list.associateBy { it.packageName }
        } catch (_: Exception) {
            emptyMap()
        }
    }
}
