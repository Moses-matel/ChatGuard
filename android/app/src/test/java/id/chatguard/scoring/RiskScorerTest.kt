package id.chatguard.scoring

import id.chatguard.analyzer.FileInspectionResult
import id.chatguard.core.model.FileType
import id.chatguard.core.model.OfficialAppEntry
import id.chatguard.core.model.ReputationResponse
import id.chatguard.core.model.Signal
import id.chatguard.core.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

class RiskScorerTest {

    private val bcaPackage = "com.bca"
    private val bcaCert = "3B8B82B56C7A0C9A57D87140B48616AC75C293A60B3F4F0E4800FA739D80EAE8"
    private val allowlist = mapOf(
        bcaPackage to OfficialAppEntry(
            packageName = bcaPackage,
            appName = "BCA Mobile",
            certSha256 = bcaCert,
            category = "BANK"
        ),
        "id.bmri.livin" to OfficialAppEntry(
            packageName = "id.bmri.livin",
            appName = "Livin' by Mandiri",
            certSha256 = "8A127FBC2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A",
            category = "BANK"
        )
    )

    private val sensitivePerms = listOf(
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
    )

    @Test
    fun `official BCA apk with sensitive permissions and matching cert scores AMAN`() {
        val inspection = FileInspectionResult(
            fileName = "BCA_Mobile.apk",
            fileType = FileType.APK,
            sha256 = "a".repeat(64),
            packageName = bcaPackage,
            certSha256 = bcaCert,
            permissions = sensitivePerms,
            signals = listOf(
                Signal("APK_SENSITIVE_PERMISSIONS", 35, "Requests sensitive permissions: READ_SMS")
            )
        )

        val report = RiskScorer.evaluate(
            inspection = inspection,
            reputation = null,
            allowlist = allowlist,
            fromChat = true
        )

        assertEquals(Verdict.AMAN, report.verdict)
    }

    @Test
    fun `official app verified via cloud match scores AMAN unless cloud verdict is malicious`() {
        val inspection = FileInspectionResult(
            fileName = "UnknownOfficial.apk",
            fileType = FileType.APK,
            sha256 = "b".repeat(64),
            packageName = "id.some.bank",
            certSha256 = "c".repeat(64),
            permissions = listOf("android.permission.READ_SMS"),
            signals = listOf(Signal("APK_SENSITIVE_PERMISSIONS", 35, "READ_SMS"))
        )

        val cleanCloud = ReputationResponse(
            verdict = "clean",
            officialCertMatch = true
        )
        val cleanReport = RiskScorer.evaluate(inspection, cleanCloud, allowlist, fromChat = true)
        assertEquals(Verdict.AMAN, cleanReport.verdict)

        val maliciousCloud = ReputationResponse(
            verdict = "malicious",
            threatCategory = "BANKING_TROJAN",
            officialCertMatch = true
        )
        val maliciousReport = RiskScorer.evaluate(inspection, maliciousCloud, allowlist, fromChat = true)
        assertEquals(Verdict.BERBAHAYA, maliciousReport.verdict)
    }

    @Test
    fun `impersonated BCA apk with mismatched cert scores BERBAHAYA with APK_IMPERSONATION`() {
        val inspection = FileInspectionResult(
            fileName = "BCA_Update.apk",
            fileType = FileType.APK,
            sha256 = "d".repeat(64),
            packageName = bcaPackage,
            certSha256 = "F".repeat(64),
            permissions = listOf("android.permission.READ_SMS"),
            signals = listOf(Signal("APK_SENSITIVE_PERMISSIONS", 35, "READ_SMS"))
        )

        val report = RiskScorer.evaluate(inspection, null, allowlist, fromChat = true)

        assertEquals(Verdict.BERBAHAYA, report.verdict)
        assertTrue(report.score >= 70)
        assertTrue(report.signals.any { it.code == "APK_IMPERSONATION" })
    }

    @Test
    fun `unknown apk with READ_SMS only and no corroborating risk is not BERBAHAYA or MENCURIGAKAN`() {
        val inspection = FileInspectionResult(
            fileName = "SmsHelper.apk",
            fileType = FileType.APK,
            sha256 = "e".repeat(64),
            packageName = "com.example.smshelper",
            certSha256 = "1".repeat(64),
            permissions = sensitivePerms,
            signals = listOf(Signal("APK_SENSITIVE_PERMISSIONS", 35, "READ_SMS, READ_CONTACTS"))
        )

        val report = RiskScorer.evaluate(inspection, null, allowlist, fromChat = true)

        assertNotEquals(Verdict.BERBAHAYA, report.verdict)
        assertNotEquals(Verdict.MENCURIGAKAN, report.verdict)
        assertEquals(Verdict.AMAN, report.verdict)
    }

    @Test
    fun `unknown apk with sensitive permissions plus raw IP URL from chat scores BERBAHAYA`() {
        val inspection = FileInspectionResult(
            fileName = "Undangan_Nikah.apk",
            fileType = FileType.APK,
            sha256 = "f".repeat(64),
            packageName = "com.scam.undangan",
            certSha256 = "2".repeat(64),
            permissions = listOf("android.permission.READ_SMS"),
            extractedUrls = listOf("http://103.45.67.89/collect"),
            signals = listOf(
                Signal("APK_SENSITIVE_PERMISSIONS", 35, "READ_SMS"),
                Signal("APK_RAW_IP_URL", 40, "APK contains raw IPv4 URL")
            )
        )

        val report = RiskScorer.evaluate(inspection, null, allowlist, fromChat = true)

        assertEquals(Verdict.BERBAHAYA, report.verdict)
    }

    @Test
    fun `archive critical signals always score BERBAHAYA`() {
        val criticalArchiveSignals = listOf(
            "ARCHIVE_PATH_TRAVERSAL",
            "ARCHIVE_ZIP_BOMB",
            "ARCHIVE_CONTAINS_APK",
            "ARCHIVE_CONTAINS_EXECUTABLE"
        )

        criticalArchiveSignals.forEach { code ->
            val inspection = FileInspectionResult(
                fileName = "paket.zip",
                fileType = FileType.ARCHIVE,
                sha256 = "3".repeat(64),
                signals = listOf(Signal(code, 45, "Detected $code"))
            )
            val report = RiskScorer.evaluate(inspection, null, allowlist, fromChat = true)
            assertEquals("Expected BERBAHAYA for $code", Verdict.BERBAHAYA, report.verdict)
        }
    }

    @Test
    fun `pdf and office risk signals score MENCURIGAKAN or BERBAHAYA appropriately`() {
        val pdfJsOnly = FileInspectionResult(
            fileName = "invoice.pdf",
            fileType = FileType.PDF,
            sha256 = "4".repeat(64),
            signals = listOf(Signal("PDF_JAVASCRIPT", 45, "PDF contains JS"))
        )
        assertEquals(Verdict.MENCURIGAKAN, RiskScorer.evaluate(pdfJsOnly, null, allowlist).verdict)

        val pdfJsAndLaunch = FileInspectionResult(
            fileName = "invoice_exec.pdf",
            fileType = FileType.PDF,
            sha256 = "5".repeat(64),
            signals = listOf(
                Signal("PDF_JAVASCRIPT", 45, "PDF contains JS"),
                Signal("PDF_LAUNCH_ACTION", 50, "PDF launch action")
            )
        )
        assertEquals(Verdict.BERBAHAYA, RiskScorer.evaluate(pdfJsAndLaunch, null, allowlist).verdict)

        val officeMacroAndRemote = FileInspectionResult(
            fileName = "tagihan.docm",
            fileType = FileType.OFFICE,
            sha256 = "6".repeat(64),
            signals = listOf(
                Signal("OFFICE_MACRO_DETECTED", 40, "Macro detected"),
                Signal("OFFICE_REMOTE_TEMPLATE", 45, "Remote template")
            )
        )
        assertEquals(Verdict.BERBAHAYA, RiskScorer.evaluate(officeMacroAndRemote, null, allowlist).verdict)
    }

    @Test
    fun `parseFailed always scores MENCURIGAKAN and never AMAN`() {
        val inspection = FileInspectionResult(
            fileName = "corrupted.pdf",
            fileType = FileType.PDF,
            sha256 = "7".repeat(64),
            signals = listOf(Signal("PARSE_FAILED", 20, "Truncated header")),
            parseFailed = true
        )

        val report = RiskScorer.evaluate(inspection, null, allowlist, fromChat = true)

        assertEquals(Verdict.MENCURIGAKAN, report.verdict)
        assertNotEquals(Verdict.AMAN, report.verdict)
    }

    @Test
    fun `plain language explainer produces Indonesian and English explanations without technical jargon`() {
        val inspection = FileInspectionResult(
            fileName = "BCA_Update.apk",
            fileType = FileType.APK,
            sha256 = "8".repeat(64),
            packageName = bcaPackage,
            certSha256 = "9".repeat(64),
            permissions = listOf("android.permission.READ_SMS"),
            extractedUrls = listOf("http://103.45.67.89/otp"),
            signals = listOf(
                Signal("APK_SENSITIVE_PERMISSIONS", 35, "READ_SMS"),
                Signal("APK_RAW_IP_URL", 40, "Raw IP")
            )
        )
        val report = RiskScorer.evaluate(inspection, null, allowlist, fromChat = true)

        val idExplained = PlainLanguageExplainer.explain(report, Locale("in", "ID"))
        val enExplained = PlainLanguageExplainer.explain(report, Locale.ENGLISH)

        assertEquals(Verdict.BERBAHAYA, idExplained.verdict)
        assertTrue(idExplained.title.isNotBlank())
        assertTrue(idExplained.whatInside.isNotBlank())
        assertTrue(idExplained.impact.isNotBlank())

        assertEquals(Verdict.BERBAHAYA, enExplained.verdict)
        assertTrue(enExplained.title.isNotBlank())
        assertTrue(enExplained.whatInside.isNotBlank())
        assertTrue(enExplained.impact.isNotBlank())

        val forbiddenJargon = listOf(
            "axml", "sha-256", "sha256", "ole", "vba", "javascript",
            "ipv4", "openaction", "certificate", "hash", "manifest", "zip bomb"
        )
        val idCombined = "${idExplained.title} ${idExplained.whatInside} ${idExplained.impact}".lowercase(Locale.ROOT)
        val enCombined = "${enExplained.title} ${enExplained.whatInside} ${enExplained.impact}".lowercase(Locale.ROOT)

        forbiddenJargon.forEach { term ->
            assertFalse("Indonesian explanation must not contain jargon '$term'", idCombined.contains(term))
            assertFalse("English explanation must not contain jargon '$term'", enCombined.contains(term))
        }
    }
}
