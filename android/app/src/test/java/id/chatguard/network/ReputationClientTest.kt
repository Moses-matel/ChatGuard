package id.chatguard.network

import id.chatguard.core.model.ReputationResponse
import id.chatguard.core.model.VerdictFeedbackRequest
import id.chatguard.data.ReputationCacheDao
import id.chatguard.data.ReputationCacheEntity
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.TimeUnit

class FakeReputationCacheDao : ReputationCacheDao {
    val storage = mutableMapOf<String, ReputationCacheEntity>()

    override suspend fun get(sha256: String): ReputationCacheEntity? {
        return storage[sha256]
    }

    override suspend fun insert(entry: ReputationCacheEntity) {
        storage[entry.sha256] = entry
    }

    override suspend fun deleteOlderThan(cutoffTimestamp: Long) {
        storage.entries.removeIf { it.value.cachedAt < cutoffTimestamp }
    }

    override suspend fun clear() {
        storage.clear()
    }
}

class ReputationClientTest {

    private lateinit var server: MockWebServer
    private lateinit var cacheDao: FakeReputationCacheDao

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        cacheDao = FakeReputationCacheDao()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun check_returnsParsedReputationResponse_whenServerReturns200Ok() = runTest {
        val jsonResponse = """
            {
                "verdict": "malicious",
                "threatCategory": "Trojan.Spy.Agent",
                "officialCertMatch": false,
                "flaggedUrls": ["https://evil-bank.example/login"]
            }
        """.trimIndent()
        server.enqueue(MockResponse().setResponseCode(200).setBody(jsonResponse))

        val client = ReputationClient(
            baseUrlProvider = { server.url("/").toString() },
            cacheDao = cacheDao
        )

        val response = client.check(
            sha256 = "dummy-sha256-hash",
            urls = listOf("https://evil-bank.example/login"),
            certSha256 = "dummy-cert-sha256"
        )

        assertNotNull("Response must not be null", response)
        assertEquals("malicious", response?.verdict)
        assertEquals("Trojan.Spy.Agent", response?.threatCategory)
        assertEquals(false, response?.officialCertMatch)
        assertEquals(listOf("https://evil-bank.example/login"), response?.flaggedUrls)

        val request = server.takeRequest(1, TimeUnit.SECONDS)
        assertNotNull(request)
        assertEquals("/v1/check", request?.path)
        assertEquals("POST", request?.method)

        val jsonBody = JSONObject(request!!.body.readUtf8())
        assertEquals("dummy-sha256-hash", jsonBody.getString("sha256"))
        assertEquals("dummy-cert-sha256", jsonBody.getString("cert_sha256"))
        assertEquals(1, jsonBody.getJSONArray("urls").length())
    }

    @Test
    fun check_hitsCacheOnSecondCallWithoutQueryingServerAgain() = runTest {
        val jsonResponse = """
            {
                "verdict": "suspicious",
                "threatCategory": "Adware",
                "officialCertMatch": null,
                "flaggedUrls": []
            }
        """.trimIndent()
        server.enqueue(MockResponse().setResponseCode(200).setBody(jsonResponse))

        val client = ReputationClient(
            baseUrlProvider = { server.url("/").toString() },
            cacheDao = cacheDao
        )

        val sha = "cached-sha-12345"
        val response1 = client.check(sha, emptyList(), null)
        assertNotNull(response1)
        assertEquals("suspicious", response1?.verdict)
        assertEquals(1, server.requestCount)

        // Second call with same sha256 should hit cache
        val response2 = client.check(sha, emptyList(), null)
        assertNotNull(response2)
        assertEquals("suspicious", response2?.verdict)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun check_doesNotUseExpiredCache() = runTest {
        var currentTime = 1_000_000L
        val client = ReputationClient(
            baseUrlProvider = { server.url("/").toString() },
            cacheDao = cacheDao,
            currentTimeProvider = { currentTime }
        )

        val sha = "sha-expiring"
        cacheDao.insert(
            ReputationCacheEntity(
                sha256 = sha,
                verdict = "clean",
                threatCategory = null,
                officialCertMatch = true,
                flaggedUrls = emptyList(),
                cachedAt = currentTime
            )
        )

        // 25 hours later (24h TTL expired)
        currentTime += (25 * 60 * 60 * 1000L)

        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("""{"verdict": "malicious", "threatCategory": "NewThreat"}""")
        )

        val response = client.check(sha, emptyList(), null)
        assertNotNull(response)
        assertEquals("malicious", response?.verdict)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun check_limitsUrlsTo50AndNeverSendsRawFileBytesOrFilenames() = runTest {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"verdict": "clean"}"""))

        val client = ReputationClient(
            baseUrlProvider = { server.url("").toString() },
            cacheDao = cacheDao
        )

        val largeUrlList = (1..75).map { "https://example.com/item/$it" }
        client.check(
            sha256 = "hash123",
            urls = largeUrlList,
            certSha256 = null
        )

        val request = server.takeRequest(1, TimeUnit.SECONDS)
        assertNotNull(request)
        val bodyStr = request!!.body.readUtf8()
        val json = JSONObject(bodyStr)

        assertEquals(50, json.getJSONArray("urls").length())
        assertEquals("hash123", json.getString("sha256"))
        assertFalse("Request must not contain fileName", json.has("fileName"))
        assertFalse("Request must not contain fileBytes", json.has("fileBytes"))
        assertFalse("Request must not contain bytes", json.has("bytes"))
    }

    @Test
    fun check_returnsNullOnServerTimeoutCleanlyWithoutThrowing() = runTest {
        server.enqueue(
            MockResponse()
                .setHeadersDelay(1000, TimeUnit.MILLISECONDS)
                .setBody("""{"verdict": "malicious"}""")
        )

        val client = ReputationClient(
            baseUrlProvider = { server.url("/").toString() },
            cacheDao = cacheDao,
            timeoutMs = 150L
        )

        val response = client.check("timeout-sha", emptyList(), null)
        assertNull("Timed out request must return null", response)
    }

    @Test
    fun check_returnsNullOnHttp500CleanlyWithoutThrowing() = runTest {
        server.enqueue(MockResponse().setResponseCode(500).setBody("Internal Server Error"))

        val client = ReputationClient(
            baseUrlProvider = { server.url("/").toString() },
            cacheDao = cacheDao
        )

        val response = client.check("error-sha", emptyList(), null)
        assertNull("500 response must return null", response)
    }

    @Test
    fun check_returnsNullOnMalformedJsonCleanlyWithoutThrowing() = runTest {
        server.enqueue(MockResponse().setResponseCode(200).setBody("<html>Not JSON</html>"))

        val client = ReputationClient(
            baseUrlProvider = { server.url("/").toString() },
            cacheDao = cacheDao
        )

        val response = client.check("malformed-sha", emptyList(), null)
        assertNull("Malformed response must return null", response)
    }

    @Test
    fun check_parsesSnakeCaseResponseFieldsCorrectly() = runTest {
        val snakeCaseJson = """
            {
                "verdict": "suspicious",
                "threat_category": "Spyware.Banker",
                "official_cert_match": false,
                "flagged_urls": ["https://phishing.site/bank"]
            }
        """.trimIndent()
        server.enqueue(MockResponse().setResponseCode(200).setBody(snakeCaseJson))

        val client = ReputationClient(
            baseUrlProvider = { server.url("/").toString() },
            cacheDao = cacheDao
        )

        val response = client.check("snake-sha", emptyList(), null)
        assertNotNull(response)
        assertEquals("suspicious", response?.verdict)
        assertEquals("Spyware.Banker", response?.threatCategory)
        assertEquals(false, response?.officialCertMatch)
        assertEquals(listOf("https://phishing.site/bank"), response?.flaggedUrls)
    }

    @Test
    fun check_handlesNullFlaggedUrlsCleanly() = runTest {
        val jsonWithNullUrls = """
            {
                "verdict": "suspicious",
                "threat_category": "Spyware",
                "official_cert_match": null,
                "flagged_urls": null
            }
        """.trimIndent()
        server.enqueue(MockResponse().setResponseCode(200).setBody(jsonWithNullUrls))

        val client = ReputationClient(
            baseUrlProvider = { server.url("/").toString() },
            cacheDao = cacheDao
        )

        val response = client.check("null-urls-sha", emptyList(), null)
        assertNotNull(response)
        assertEquals("suspicious", response?.verdict)
        assertEquals("Spyware", response?.threatCategory)
        assertNull(response?.officialCertMatch)
        assertEquals(emptyList<String>(), response?.flaggedUrls)
    }

    @Test
    fun check_worksWhenCacheDaoIsNull() = runTest {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"verdict": "clean"}"""))

        val client = ReputationClient(
            baseUrlProvider = { server.url("/").toString() },
            cacheDao = null
        )

        val response = client.check("no-dao-sha", emptyList(), null)
        assertNotNull(response)
        assertEquals("clean", response?.verdict)
    }

    @Test
    fun submitReport_returnsTrueOn200AndTruncatesUserNoteTo500Chars() = runTest {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"status":"ok"}"""))

        val client = ReputationClient(
            baseUrlProvider = { server.url("/").toString() }
        )

        val longNote = "X".repeat(650)
        val report = VerdictFeedbackRequest(
            sha256 = "report-sha-999",
            fileType = "APK",
            packageName = "com.fake.bank",
            certSha256 = "fake-cert-sha",
            shownVerdict = "BERBAHAYA",
            userNote = longNote
        )

        val success = client.submitReport(report)
        assertTrue("submitReport must return true on 200 OK", success)

        val request = server.takeRequest(1, TimeUnit.SECONDS)
        assertNotNull(request)
        assertEquals("/v1/report", request?.path)
        assertEquals("POST", request?.method)

        val json = JSONObject(request!!.body.readUtf8())
        assertEquals("report-sha-999", json.getString("sha256"))
        assertEquals("APK", json.getString("fileType"))
        assertEquals("com.fake.bank", json.getString("packageName"))
        assertEquals("fake-cert-sha", json.getString("certSha256"))
        assertEquals("BERBAHAYA", json.getString("shownVerdict"))
        assertEquals(500, json.getString("userNote").length)
        assertFalse("Report must not send raw file bytes or filenames", json.has("fileName"))
        assertFalse("Report must not send raw file bytes or filenames", json.has("fileBytes"))
    }

    @Test
    fun submitReport_returnsFalseOnHttpErrorCleanlyWithoutThrowing() = runTest {
        server.enqueue(MockResponse().setResponseCode(500).setBody("Server Error"))

        val client = ReputationClient(
            baseUrlProvider = { server.url("/").toString() }
        )

        val report = VerdictFeedbackRequest(
            sha256 = "report-sha-err",
            fileType = "PDF",
            shownVerdict = "MENCURIGAKAN"
        )

        val result = client.submitReport(report)
        assertFalse("submitReport must return false on 500", result)
    }

    @Test
    fun submitReport_returnsFalseOnTimeoutCleanlyWithoutThrowing() = runTest {
        server.enqueue(
            MockResponse()
                .setHeadersDelay(1000, TimeUnit.MILLISECONDS)
                .setResponseCode(200)
                .setBody("""{"status":"ok"}""")
        )

        val client = ReputationClient(
            baseUrlProvider = { server.url("/").toString() },
            timeoutMs = 150L
        )

        val report = VerdictFeedbackRequest(
            sha256 = "report-sha-timeout",
            fileType = "OFFICE",
            shownVerdict = "AMAN"
        )

        val result = client.submitReport(report)
        assertFalse("submitReport must return false on timeout", result)
    }

    @Test
    fun reputationCacheEntity_mapsToAndFromReputationResponseCorrectly() {
        val response = ReputationResponse(
            verdict = "malicious",
            threatCategory = "Ransomware",
            officialCertMatch = false,
            flaggedUrls = listOf("https://bad1.com", "https://bad2.com")
        )

        val entity = ReputationCacheEntity.fromResponse(
            sha256 = "test-sha",
            response = response,
            cachedAt = 123456789L
        )

        assertEquals("test-sha", entity.sha256)
        assertEquals("malicious", entity.verdict)
        assertEquals("Ransomware", entity.threatCategory)
        assertEquals(false, entity.officialCertMatch)
        assertEquals(listOf("https://bad1.com", "https://bad2.com"), entity.flaggedUrls)
        assertEquals(123456789L, entity.cachedAt)

        val converted = entity.toReputationResponse()
        assertEquals(response, converted)
    }
}
