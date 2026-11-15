package id.chatguard.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.InputStream

class AllowlistLoaderTest {

    private fun sampleJsonStream(): InputStream {
        val json = """
            [
              {
                "packageName": "com.bca",
                "appName": "BCA Mobile",
                "certSha256": "3B8B82B56C7A0C9A57D87140B48616AC75C293A60B3F4F0E4800FA739D80EAE8",
                "category": "BANK"
              },
              {
                "packageName": "com.telkom.indonesiamobile",
                "appName": "MyTelkomsel",
                "certSha256": "4A1F6E22728CE7C31688D2FA658826D002B41BC81B348EE8A6D2F9EC4D1794A1",
                "category": "TELCO"
              }
            ]
        """.trimIndent()
        return ByteArrayInputStream(json.toByteArray(Charsets.UTF_8))
    }

    @Test
    fun `load returns curated indonesian banking and ewallet certs`() {
        val allowlist = OfficialCertAllowlist.loadFromStream(sampleJsonStream())
        assertTrue(allowlist.containsKey("com.bca"))
        assertEquals(64, allowlist["com.bca"]!!.certSha256.length)
        assertEquals("BCA Mobile", allowlist["com.bca"]!!.appName)
        assertEquals("BANK", allowlist["com.bca"]!!.category)
    }

    @Test
    fun `handles empty stream gracefully`() {
        val allowlist = OfficialCertAllowlist.loadFromStream(ByteArrayInputStream("[]".toByteArray()))
        assertTrue(allowlist.isEmpty())
    }

    @Test
    fun `handles invalid json gracefully without throwing`() {
        val allowlist = OfficialCertAllowlist.loadFromStream(ByteArrayInputStream("not a json".toByteArray()))
        assertTrue(allowlist.isEmpty())
    }

    @Test
    fun `bundled asset file contains all curated indonesian entries`() {
        val assetFile = java.io.File("src/main/assets/indonesian_official_certs.json")
        assertTrue("Asset file must exist", assetFile.exists())
        val allowlist = assetFile.inputStream().use { OfficialCertAllowlist.loadFromStream(it) }
        assertTrue("Allowlist must contain BCA", allowlist.containsKey("com.bca"))
        assertTrue("Allowlist must contain BRImo", allowlist.containsKey("id.co.bri.brimo"))
        assertTrue("Allowlist must contain Mandiri", allowlist.containsKey("src.com.mandiri.livin"))
        assertTrue("Allowlist must contain DANA", allowlist.containsKey("id.dana"))
        assertTrue("Allowlist must contain Gojek", allowlist.containsKey("com.gojek.app"))
        assertTrue("Allowlist must contain J&T", allowlist.containsKey("com.jet.express"))
        assertTrue("Allowlist must contain SatuSehat", allowlist.containsKey("id.kemkes.satusehat"))
        assertTrue("Allowlist has at least 20 entries", allowlist.size >= 20)
        allowlist.values.forEach { entry ->
            assertEquals("SHA256 must be 64 hex chars for ${entry.packageName}", 64, entry.certSha256.length)
            assertTrue("appName must not be blank for ${entry.packageName}", entry.appName.isNotBlank())
            assertTrue("category must not be blank for ${entry.packageName}", entry.category.isNotBlank())
        }
    }
}
