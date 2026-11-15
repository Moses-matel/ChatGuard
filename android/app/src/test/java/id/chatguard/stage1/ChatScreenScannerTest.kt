package id.chatguard.stage1

import id.chatguard.core.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ChatScreenScannerTest {

    @Test
    fun `detects suspicious pdf filename in WhatsApp screen text`() {
        val scanner = ChatScreenScanner(cooldownMs = 15_000L)
        val alerts = scanner.findAlerts(
            packageName = "com.whatsapp",
            visibleTexts = listOf("11:40", "Undangan_Test_ChatGuard.pdf", "431 B"),
            nowMs = 1_000L
        )
        assertEquals(1, alerts.size)
        assertEquals("Undangan_Test_ChatGuard.pdf", alerts[0].fileName)
        assertEquals(Verdict.MENCURIGAKAN, alerts[0].verdict)
    }

    @Test
    fun `deduplicates repeated alerts within cooldown window and re-alerts after expiry`() {
        val scanner = ChatScreenScanner(cooldownMs = 600_000L)
        val first = scanner.findAlerts(
            packageName = "com.whatsapp",
            visibleTexts = listOf("Undangan_Test_ChatGuard.pdf"),
            nowMs = 1_000L
        )
        assertEquals(1, first.size)

        val second = scanner.findAlerts(
            packageName = "com.whatsapp",
            visibleTexts = listOf("Undangan_Test_ChatGuard.pdf"),
            nowMs = 120_000L
        )
        assertTrue(second.isEmpty())

        val afterCooldown = scanner.findAlerts(
            packageName = "com.whatsapp",
            visibleTexts = listOf("Undangan_Test_ChatGuard.pdf"),
            nowMs = 700_000L
        )
        assertEquals(1, afterCooldown.size)
    }

    @Test
    fun `ignores unsupported packages and benign media filenames`() {
        val scanner = ChatScreenScanner()
        val unsupported = scanner.findAlerts(
            packageName = "com.android.chrome",
            visibleTexts = listOf("Undangan_Nikah.pdf.apk"),
            nowMs = 1_000L
        )
        assertTrue(unsupported.isEmpty())

        val benign = scanner.findAlerts(
            packageName = "com.whatsapp",
            visibleTexts = listOf("liburan.jpg", "Halo apa kabar?"),
            nowMs = 1_000L
        )
        assertTrue(benign.isEmpty())
    }
}
