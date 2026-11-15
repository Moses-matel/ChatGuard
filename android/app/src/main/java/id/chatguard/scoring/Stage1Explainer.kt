package id.chatguard.scoring

import id.chatguard.core.model.NotificationAlert
import id.chatguard.core.model.Verdict

data class Stage1Explanation(
    val title: String,
    val whatFound: String,
    val impact: String,
    val advice: String,
    val lessonTip: String,
    val technicalSignals: String
)

object Stage1Explainer {

    fun explain(
        alert: NotificationAlert,
        isBlocked: Boolean = false,
        isIndonesian: Boolean = true
    ): Stage1Explanation {
        val reasons = alert.reasons.toSet()
        val hasDoubleExt = "DOUBLE_EXTENSION_APK" in reasons
        val hasRiskyExec = "RISKY_EXECUTABLE_EXTENSION" in reasons
        val hasApk = "APK_VIA_CHAT" in reasons
        val hasLure = "LURE_KEYWORDS_ID" in reasons

        val signalCodes = buildList {
            addAll(alert.reasons)
            if (isBlocked && "BLOCKED_BY_USER" !in alert.reasons) {
                add("BLOCKED_BY_USER")
            }
        }.ifEmpty { listOf("SUSPICIOUS_FILENAME") }
        val ext = alert.fileName.substringAfterLast('.', "").ifBlank { "-" }
        val technicalSignals = if (isIndonesian) {
            "• Sinyal: ${signalCodes.joinToString(", ")}\n• Ekstensi: .$ext | Sumber: ${alert.sourcePackage}\n• Tahap: Stage 1 (Pra-Unduh)"
        } else {
            "• Signals: ${signalCodes.joinToString(", ")}\n• Extension: .$ext | Source: ${alert.sourcePackage}\n• Stage: Stage 1 (Pre-Download)"
        }

        if (isIndonesian) {
            val title = when {
                isBlocked -> "Diblokir: File ini sudah Anda tandai berbahaya"
                alert.verdict == Verdict.BERBAHAYA -> "Berbahaya: Jangan unduh atau buka file ini"
                else -> "Mencurigakan: Waspada sebelum mengunduh"
            }

            val foundParts = mutableListOf<String>()
            if (hasDoubleExt) {
                foundParts += "File menyamar sebagai dokumen/foto tetapi sebenarnya aplikasi Android (.apk) dengan ekstensi ganda (${alert.fileName})."
            } else if (hasRiskyExec) {
                foundParts += "File memakai ekstensi skrip/eksekusi berisiko tinggi (${alert.fileName})."
            } else if (hasApk) {
                foundParts += "Pengirim membagikan file aplikasi Android (.apk) langsung lewat chat (${alert.fileName})."
            }
            if (hasLure) {
                foundParts += "Nama file memakai kata pancingan penipuan (seperti undangan, resi, tilang, tagihan, atau kurir) untuk memicu kepanikan/rasa penasaran."
            }
            if (isBlocked) {
                foundParts += "File ini sebelumnya sudah Anda blokir di ChatGuard."
            }
            if (foundParts.isEmpty()) {
                foundParts += "Terdeteksi file mencurigakan (${alert.fileName}) di layar/notifikasi chat."
            }

            val impact = when {
                hasDoubleExt || hasApk ->
                    "Jika diunduh dan dipasang, aplikasi ini berpotensi membaca SMS/kode OTP bank atau e-wallet dan mengambil alih akun Anda."
                hasRiskyExec ->
                    "Membuka file ini dapat menjalankan perintah berbahaya atau mengarahkan Anda ke pencurian data akun."
                else ->
                    "File dokumen/PDF mencurigakan bisa berisi tautan phishing, skrip berbahaya, atau mengarahkan Anda ke halaman penipuan."
            }

            val advice = when {
                isBlocked ->
                    "Tetap abaikan file ini. Jangan unduh, jangan buka, dan hapus pesan jika perlu."
                hasDoubleExt || hasApk || hasRiskyExec ->
                    "Jangan unduh dan jangan pernah pasang file ini. Blokir file ini sekarang dan konfirmasi langsung ke pengirim lewat telepon."
                else ->
                    "Jangan langsung dibuka. Pastikan keasliannya langsung ke pengirim resmi atau pindai isi file lewat ChatGuard terlebih dahulu."
            }

            val lessonTip = when {
                hasDoubleExt ->
                    "Penipu sering menamai aplikasi jahat seperti 'Undangan.pdf.apk'. Selalu perhatikan akhiran paling belakang (.apk)."
                hasLure ->
                    "Modus penipuan sering memakai kata 'Undangan', 'Resi', 'Tilang', atau 'Tagihan' agar korban buru-buru membuka tanpa curiga."
                hasApk ->
                    "Aplikasi resmi selalu dipasang lewat Google Play Store, bukan lewat kiriman file .apk di chat."
                else ->
                    "Selalu cek nama file dan pengirim sebelum mengunduh atau membuka lampiran dari chat."
            }

            return Stage1Explanation(
                title = title,
                whatFound = foundParts.joinToString(" "),
                impact = impact,
                advice = advice,
                lessonTip = lessonTip,
                technicalSignals = technicalSignals
            )
        } else {
            val title = when {
                isBlocked -> "Blocked: You marked this file as unsafe"
                alert.verdict == Verdict.BERBAHAYA -> "Dangerous: Do not download or open this file"
                else -> "Suspicious: Be careful before downloading"
            }

            val foundParts = mutableListOf<String>()
            if (hasDoubleExt) {
                foundParts += "The file disguises itself as a document/media but is actually an Android app (.apk) using a double extension (${alert.fileName})."
            } else if (hasRiskyExec) {
                foundParts += "The file uses a high-risk executable/script extension (${alert.fileName})."
            } else if (hasApk) {
                foundParts += "An Android installer (.apk) was shared directly in chat (${alert.fileName})."
            }
            if (hasLure) {
                foundParts += "The filename uses common phishing lure words (such as invitation, receipt, ticket, or bill)."
            }
            if (isBlocked) {
                foundParts += "You previously blocked this file in ChatGuard."
            }
            if (foundParts.isEmpty()) {
                foundParts += "A suspicious file (${alert.fileName}) was detected in chat."
            }

            val impact = when {
                hasDoubleExt || hasApk ->
                    "If installed, it may steal SMS/OTP codes for your bank or e-wallet and take over your accounts."
                hasRiskyExec ->
                    "Opening this file may run malicious commands or lead to credential theft."
                else ->
                    "Suspicious documents may contain phishing links or hidden scripts designed to steal personal data."
            }

            val advice = when {
                isBlocked -> "Keep ignoring this file. Do not download or open it."
                hasDoubleExt || hasApk || hasRiskyExec ->
                    "Do not download or install this file. Block it now and verify with the sender through an official channel."
                else ->
                    "Do not open immediately. Verify with the official sender or inspect the file with ChatGuard first."
            }

            val lessonTip = when {
                hasDoubleExt ->
                    "Attackers disguise apps as 'Invite.pdf.apk'. Always check the very last extension (.apk)."
                hasLure ->
                    "Scammers use urgent words like 'Invitation', 'Receipt', or 'Fine' to make victims open files hastily."
                hasApk ->
                    "Legitimate apps come from Google Play Store, not raw .apk files sent in chat."
                else ->
                    "Always verify the filename and sender before downloading chat attachments."
            }

            return Stage1Explanation(
                title = title,
                whatFound = foundParts.joinToString(" "),
                impact = impact,
                advice = advice,
                lessonTip = lessonTip,
                technicalSignals = technicalSignals
            )
        }
    }
}
