package id.chatguard.stage1

import id.chatguard.core.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NotificationAnalyzerTest {

    @Test
    fun `flags double extension pdf apk in whatsapp notification`() {
        val alert = NotificationAnalyzer().analyze(
            packageName = "com.whatsapp",
            title = "+62 812-3456-7890",
            text = "Undangan_Pernikahan.pdf.apk (3.1 MB) — Mohon dibuka ya"
        )
        assertNotNull(alert)
        assertEquals(Verdict.BERBAHAYA, alert!!.verdict)
        assertEquals("Undangan_Pernikahan.pdf.apk", alert.fileName)
        assertEquals("com.whatsapp", alert.sourcePackage)
        assertEquals("+62 812-3456-7890", alert.sender)
        assertTrue(alert.reasons.contains("DOUBLE_EXTENSION_APK"))
        assertTrue(alert.reasons.contains("APK_VIA_CHAT"))
        assertTrue(alert.reasons.contains("LURE_KEYWORDS_ID"))
    }

    @Test
    fun `flags double extension jpg apk without lure keywords as BERBAHAYA`() {
        val alert = NotificationAnalyzer.analyze(
            packageName = "com.whatsapp",
            title = "Budi",
            text = "Foto.jpg.apk"
        )
        assertNotNull(alert)
        assertEquals(Verdict.BERBAHAYA, alert!!.verdict)
        assertEquals("Foto.jpg.apk", alert.fileName)
        assertTrue(alert.reasons.contains("DOUBLE_EXTENSION_APK"))
        assertTrue(alert.reasons.contains("APK_VIA_CHAT"))
        assertFalse(alert.reasons.contains("LURE_KEYWORDS_ID"))
    }

    @Test
    fun `flags apk with lure keyword as BERBAHAYA`() {
        val alert = NotificationAnalyzer.analyze(
            packageName = "com.whatsapp.w4b",
            title = "Surat Tilang Kepolisian",
            text = "surat_tilang.apk"
        )
        assertNotNull(alert)
        assertEquals(Verdict.BERBAHAYA, alert!!.verdict)
        assertEquals("surat_tilang.apk", alert.fileName)
        assertEquals("com.whatsapp.w4b", alert.sourcePackage)
        assertTrue(alert.reasons.contains("APK_VIA_CHAT"))
        assertTrue(alert.reasons.contains("LURE_KEYWORDS_ID"))
    }

    @Test
    fun `flags apk without lure keywords as MENCURIGAKAN`() {
        val alert = NotificationAnalyzer.analyze(
            packageName = "org.telegram.messenger",
            title = "Dev Group",
            text = "test_build_v2.apk"
        )
        assertNotNull(alert)
        assertEquals(Verdict.MENCURIGAKAN, alert!!.verdict)
        assertEquals("test_build_v2.apk", alert.fileName)
        assertEquals("org.telegram.messenger", alert.sourcePackage)
        assertTrue(alert.reasons.contains("APK_VIA_CHAT"))
        assertFalse(alert.reasons.contains("LURE_KEYWORDS_ID"))
        assertFalse(alert.reasons.contains("DOUBLE_EXTENSION_APK"))
    }

    @Test
    fun `flags risky executable extensions as BERBAHAYA`() {
        val extensions = listOf("exe", "bat", "cmd", "vbs", "js", "scr")
        for (ext in extensions) {
            val alert = NotificationAnalyzer.analyze(
                packageName = "com.whatsapp",
                title = "Unknown Sender",
                text = "payload.$ext (100 KB)"
            )
            assertNotNull("Extension .$ext must produce an alert", alert)
            assertEquals("Extension .$ext must be BERBAHAYA", Verdict.BERBAHAYA, alert!!.verdict)
            assertEquals("payload.$ext", alert.fileName)
            assertTrue("Extension .$ext must contain RISKY_EXECUTABLE_EXTENSION", alert.reasons.contains("RISKY_EXECUTABLE_EXTENSION"))
        }
    }

    @Test
    fun `flags document with lure keyword as MENCURIGAKAN`() {
        val alert = NotificationAnalyzer.analyze(
            packageName = "com.whatsapp",
            title = "J&T Express",
            text = "resi_pengiriman.pdf (500 KB)"
        )
        assertNotNull(alert)
        assertEquals(Verdict.MENCURIGAKAN, alert!!.verdict)
        assertEquals("resi_pengiriman.pdf", alert.fileName)
        assertTrue(alert.reasons.contains("LURE_KEYWORDS_ID"))
    }

    @Test
    fun `normal pdf without lure returns null or AMAN`() {
        val alert = NotificationAnalyzer.analyze(
            packageName = "com.whatsapp",
            title = "Alice",
            text = "laporan_keuangan.pdf (1.2 MB)"
        )
        assertTrue("Normal pdf without lure must return null or AMAN", alert == null || alert.verdict == Verdict.AMAN)
    }

    @Test
    fun `unsupported package returns null`() {
        val alert = NotificationAnalyzer.analyze(
            packageName = "com.facebook.orca",
            title = "Attacker",
            text = "Undangan_Pernikahan.pdf.apk"
        )
        assertNull(alert)
    }

    @Test
    fun `plain chat message without attachment clues returns null`() {
        val alert = NotificationAnalyzer.analyze(
            packageName = "com.whatsapp",
            title = "Mom",
            text = "Halo apa kabar nak? Nanti malam pulang jam berapa?"
        )
        assertNull(alert)
    }

    @Test
    fun `handles all ten Indonesian lure keywords correctly`() {
        val keywords = listOf(
            "undangan",
            "tilang",
            "resi",
            "tagihan",
            "blokir",
            "hadiah",
            "bpjs",
            "pajak",
            "kurir",
            "paket"
        )
        for (keyword in keywords) {
            val alert = NotificationAnalyzer.analyze(
                packageName = "com.whatsapp",
                title = "Info $keyword",
                text = "dokumen_$keyword.apk"
            )
            assertNotNull("Alert must be non-null for keyword: $keyword", alert)
            assertEquals("Verdict must be BERBAHAYA for keyword: $keyword with apk", Verdict.BERBAHAYA, alert!!.verdict)
            assertTrue("Reasons must include LURE_KEYWORDS_ID for: $keyword", alert.reasons.contains("LURE_KEYWORDS_ID"))
            assertTrue("Reasons must include APK_VIA_CHAT for: $keyword", alert.reasons.contains("APK_VIA_CHAT"))
        }
    }

    @Test
    fun `handles filename with spaces and emoji prefix`() {
        val alert = NotificationAnalyzer.analyze(
            packageName = "com.whatsapp",
            title = "Teman Kantor",
            text = "📄 Undangan Pernikahan Budi & Ani.pdf.apk (2.8 MB)"
        )
        assertNotNull(alert)
        assertEquals(Verdict.BERBAHAYA, alert!!.verdict)
        assertEquals("Undangan Pernikahan Budi & Ani.pdf.apk", alert.fileName)
        assertTrue(alert.reasons.contains("DOUBLE_EXTENSION_APK"))
        assertTrue(alert.reasons.contains("LURE_KEYWORDS_ID"))
    }

    @Test
    fun `regresi_linier pdf does not trigger LURE_KEYWORDS_ID`() {
        val alert = NotificationAnalyzer.analyze(
            packageName = "com.whatsapp",
            title = "Dosen Statistika",
            text = "regresi_linier.pdf"
        )
        assertNull("regresi_linier.pdf should produce null alert (clean file)", alert)

        val cleanAlert = NotificationAnalyzer.analyze(
            packageName = "com.whatsapp",
            title = "Dosen Statistika",
            text = "regresi_linier.pdf",
            returnCleanAlert = true
        )
        assertNotNull(cleanAlert)
        assertEquals(Verdict.AMAN, cleanAlert!!.verdict)
        assertFalse(
            "regresi_linier.pdf must NOT trigger LURE_KEYWORDS_ID",
            cleanAlert.reasons.contains("LURE_KEYWORDS_ID")
        )

        // With .apk extension, regresi_linier.apk must be MENCURIGAKAN, not BERBAHAYA
        val apkAlert = NotificationAnalyzer.analyze(
            packageName = "com.whatsapp",
            title = "Dev",
            text = "regresi_linier.apk"
        )
        assertNotNull(apkAlert)
        assertEquals(Verdict.MENCURIGAKAN, apkAlert!!.verdict)
        assertFalse(
            "regresi_linier.apk must NOT trigger LURE_KEYWORDS_ID",
            apkAlert.reasons.contains("LURE_KEYWORDS_ID")
        )
    }

    @Test
    fun `presiden document does not trigger LURE_KEYWORDS_ID`() {
        val alert = NotificationAnalyzer.analyze(
            packageName = "com.whatsapp",
            title = "Humas",
            text = "pidato_presiden.pdf"
        )
        assertNull(alert)
    }

    @Test
    fun `ChatNotificationListener processes notification and dispatches to alert listeners`() {
        val capturedAlerts = mutableListOf<id.chatguard.core.model.NotificationAlert>()
        val listener: (id.chatguard.core.model.NotificationAlert) -> Unit = { capturedAlerts.add(it) }

        ChatNotificationListener.addListener(listener)
        try {
            val service = ChatNotificationListener()

            // Exercise actual notification processing path in ChatNotificationListener
            val alert = service.processNotification(
                packageName = "com.whatsapp",
                title = "Pak RT",
                text = "Undangan_Warga.pdf.apk"
            )
            assertNotNull(alert)
            assertEquals(1, capturedAlerts.size)
            assertEquals("Undangan_Warga.pdf.apk", capturedAlerts[0].fileName)
            assertEquals(Verdict.BERBAHAYA, capturedAlerts[0].verdict)

            // AMAN verdict notifications should not dispatch alerts to listeners
            service.processNotification(
                packageName = "com.whatsapp",
                title = "Alice",
                text = "laporan.pdf"
            )
            assertEquals("AMAN notification must not dispatch alert", 1, capturedAlerts.size)

            // Direct dispatchAlert on AMAN alert should also be suppressed
            val cleanAlert = id.chatguard.core.model.NotificationAlert(
                sourcePackage = "com.whatsapp",
                sender = "Alice",
                fileName = "clean.pdf",
                verdict = Verdict.AMAN,
                reasons = emptyList()
            )
            service.dispatchAlert(cleanAlert)
            assertEquals("Direct AMAN dispatchAlert must not dispatch", 1, capturedAlerts.size)
        } finally {
            ChatNotificationListener.removeListener(listener)
            ChatNotificationListener.clearListeners()
        }
    }
}
