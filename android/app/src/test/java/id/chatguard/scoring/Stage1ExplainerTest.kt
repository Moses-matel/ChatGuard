package id.chatguard.scoring

import id.chatguard.core.model.NotificationAlert
import id.chatguard.core.model.Verdict
import org.junit.Assert.assertTrue
import org.junit.Test

class Stage1ExplainerTest {

    @Test
    fun `explains lure pdf in Indonesian with impact advice and lesson`() {
        val alert = NotificationAlert(
            sourcePackage = "com.whatsapp",
            sender = "Unknown",
            fileName = "Undangan_Test_ChatGuard.pdf",
            verdict = Verdict.MENCURIGAKAN,
            reasons = listOf("LURE_KEYWORDS_ID")
        )
        val explained = Stage1Explainer.explain(alert, isBlocked = false, isIndonesian = true)
        assertTrue(explained.whatFound.contains("pancingan", ignoreCase = true))
        assertTrue(explained.impact.contains("phishing", ignoreCase = true))
        assertTrue(explained.advice.isNotBlank())
        assertTrue(explained.lessonTip.isNotBlank())
        assertTrue(explained.technicalSignals.contains("LURE_KEYWORDS_ID"))
    }

    @Test
    fun `explains blocked double extension apk clearly`() {
        val alert = NotificationAlert(
            sourcePackage = "com.whatsapp",
            sender = "Unknown",
            fileName = "Resi_JNE.pdf.apk",
            verdict = Verdict.BERBAHAYA,
            reasons = listOf("DOUBLE_EXTENSION_APK", "APK_VIA_CHAT", "LURE_KEYWORDS_ID")
        )
        val explained = Stage1Explainer.explain(alert, isBlocked = true, isIndonesian = true)
        assertTrue(explained.title.contains("Diblokir", ignoreCase = true))
        assertTrue(explained.impact.contains("OTP", ignoreCase = true))
        assertTrue(explained.whatFound.contains("ekstensi ganda", ignoreCase = true))
    }
}
