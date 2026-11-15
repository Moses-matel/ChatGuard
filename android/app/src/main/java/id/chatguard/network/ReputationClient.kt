package id.chatguard.network

import id.chatguard.core.model.ReputationResponse
import id.chatguard.core.model.VerdictFeedbackRequest
import id.chatguard.data.ReputationCacheDao
import id.chatguard.data.ReputationCacheEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit
import kotlin.coroutines.cancellation.CancellationException

@OptIn(ExperimentalSerializationApi::class)
class ReputationClient(
    private val baseUrlProvider: () -> String,
    private val cacheDao: ReputationCacheDao? = null,
    private val timeoutMs: Long = 2000L,
    okHttpClient: OkHttpClient? = null,
    private val cacheTtlMs: Long = DEFAULT_CACHE_TTL_MS,
    private val currentTimeProvider: () -> Long = { System.currentTimeMillis() }
) {

    private val client: OkHttpClient = (okHttpClient?.newBuilder() ?: OkHttpClient.Builder())
        .connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
        .readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
        .writeTimeout(timeoutMs, TimeUnit.MILLISECONDS)
        .callTimeout(timeoutMs, TimeUnit.MILLISECONDS)
        .build()

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
        encodeDefaults = true
        explicitNulls = true
    }

    @Serializable
    private data class CheckRequestBody(
        val sha256: String,
        val urls: List<String>,
        @SerialName("cert_sha256")
        val certSha256: String? = null
    )

    suspend fun check(
        sha256: String,
        urls: List<String>,
        certSha256: String?
    ): ReputationResponse? {
        // 1. Check local Room cache first (if cacheDao != null and entry is not expired, e.g. 24h TTL)
        if (cacheDao != null) {
            try {
                val cached = cacheDao.get(sha256)
                if (cached != null) {
                    val age = currentTimeProvider() - cached.cachedAt
                    if (age in 0 until cacheTtlMs) {
                        return cached.toReputationResponse()
                    }
                }
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                // Otherwise fall back to network lookup
            }
        }

        // 2. Query network endpoint POST {baseUrl}/v1/check
        return try {
            val base = baseUrlProvider().trimEnd('/')
            val url = "$base/v1/check"
            val requestBodyObj = CheckRequestBody(
                sha256 = sha256,
                urls = urls.take(50),
                certSha256 = certSha256
            )
            val jsonBody = json.encodeToString(requestBodyObj)
            val requestBody = jsonBody.toRequestBody("application/json; charset=utf-8".toMediaType())
            val request = Request.Builder()
                .url(url)
                .post(requestBody)
                .build()

            val rawResponse = executeRequest(request) ?: return null
            val response = parseReputationResponse(rawResponse) ?: return null

            // 3. Persist successful responses to Room cache
            if (cacheDao != null) {
                try {
                    val entry = ReputationCacheEntity.fromResponse(
                        sha256 = sha256,
                        response = response,
                        cachedAt = currentTimeProvider()
                    )
                    cacheDao.insert(entry)
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    // Continue returning response even if cache write fails
                }
            }

            response
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            null
        }
    }

    suspend fun submitReport(report: VerdictFeedbackRequest): Boolean {
        return try {
            val base = baseUrlProvider().trimEnd('/')
            val url = "$base/v1/report"

            val sanitizedNote = report.userNote?.take(500)
            val sanitizedReport = if (sanitizedNote != report.userNote) {
                report.copy(userNote = sanitizedNote)
            } else {
                report
            }

            val jsonBody = json.encodeToString(sanitizedReport)
            val requestBody = jsonBody.toRequestBody("application/json; charset=utf-8".toMediaType())
            val request = Request.Builder()
                .url(url)
                .post(requestBody)
                .build()

            val statusCode = executeRequestForCode(request)
            statusCode in 200..299
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            false
        }
    }

    private suspend fun executeRequest(request: Request): String? = withContext(Dispatchers.IO) {
        try {
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    response.body?.string()
                } else {
                    null
                }
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            null
        }
    }

    private suspend fun executeRequestForCode(request: Request): Int = withContext(Dispatchers.IO) {
        try {
            client.newCall(request).execute().use { response ->
                response.body?.string()
                response.code
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            -1
        }
    }

    private fun parseReputationResponse(rawJson: String): ReputationResponse? {
        return try {
            val root = json.parseToJsonElement(rawJson).jsonObject
            val verdict = root["verdict"]?.jsonPrimitive?.contentOrNull ?: return null
            val threatCategory = (root["threatCategory"] ?: root["threat_category"])?.jsonPrimitive?.contentOrNull

            val certMatchElem = root["officialCertMatch"] ?: root["official_cert_match"]
            val officialCertMatch = certMatchElem?.let {
                it.jsonPrimitive.booleanOrNull ?: it.jsonPrimitive.contentOrNull?.toBooleanStrictOrNull()
            }

            val urlsElem = root["flaggedUrls"] ?: root["flagged_urls"]
            val flaggedUrls = (urlsElem as? JsonArray)?.mapNotNull { it.jsonPrimitive.contentOrNull } ?: emptyList()

            ReputationResponse(
                verdict = verdict,
                threatCategory = threatCategory,
                officialCertMatch = officialCertMatch,
                flaggedUrls = flaggedUrls
            )
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            null
        }
    }

    companion object {
        const val DEFAULT_CACHE_TTL_MS: Long = 24 * 60 * 60 * 1000L // 24 hours
    }
}
