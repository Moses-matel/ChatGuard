package id.chatguard.scoring

import id.chatguard.core.model.AnalysisReport
import id.chatguard.core.model.FileType
import id.chatguard.core.model.Signal
import id.chatguard.core.model.Verdict
import java.util.Locale

data class ExplainedReport(
    val verdict: Verdict,
    val title: String,
    val whatInside: String,
    val impact: String,
    val signals: List<Signal>
)

object PlainLanguageExplainer {

    fun explain(
        report: AnalysisReport,
        locale: Locale = Locale("in", "ID")
    ): ExplainedReport {
        val isIndonesian = locale.language.equals("in", ignoreCase = true) ||
            locale.language.equals("id", ignoreCase = true)

        val title = buildTitle(report.verdict, report.fileType, isIndonesian)
        val whatInside = buildWhatInside(report, isIndonesian)
        val impact = buildImpact(report, isIndonesian)

        return ExplainedReport(
            verdict = report.verdict,
            title = title,
            whatInside = whatInside,
            impact = impact,
            signals = report.signals
        )
    }

    private fun buildTitle(verdict: Verdict, fileType: FileType, isId: Boolean): String {
        return if (isId) {
            when (verdict) {
                Verdict.BERBAHAYA -> when (fileType) {
                    FileType.APK -> "Berbahaya: Aplikasi ini berisiko mencuri data"
                    else -> "Berbahaya: Jangan buka file ini"
                }
                Verdict.MENCURIGAKAN -> "Mencurigakan: Perlu kehati-hatian ekstra"
                Verdict.AMAN -> "Aman: Tidak ditemukan tanda bahaya"
            }
        } else {
            when (verdict) {
                Verdict.BERBAHAYA -> when (fileType) {
                    FileType.APK -> "Dangerous: This app may steal your data"
                    else -> "Dangerous: Do not open this file"
                }
                Verdict.MENCURIGAKAN -> "Suspicious: Extra caution needed"
                Verdict.AMAN -> "Safe: No signs of danger found"
            }
        }
    }

    private fun buildWhatInside(report: AnalysisReport, isId: Boolean): String {
        val codes = report.signals.map { it.code }.toSet()
        val findings = mutableListOf<String>()

        if ("OFFICIAL_APP_VERIFIED" in codes) {
            return if (isId) {
                "File \"${report.fileName}\" adalah aplikasi resmi yang terverifikasi."
            } else {
                "File \"${report.fileName}\" is a verified official application."
            }
        }

        if ("APK_IMPERSONATION" in codes) {
            findings += if (isId) {
                "aplikasi palsu yang meniru aplikasi resmi"
            } else {
                "a fake app impersonating an official app"
            }
        }
        if ("APK_SENSITIVE_PERMISSIONS" in codes) {
            findings += if (isId) {
                "izin untuk membaca SMS atau notifikasi (termasuk kode OTP bank/e-wallet)"
            } else {
                "permission to read SMS or notifications (including bank or e-wallet OTP codes)"
            }
        }
        if ("APK_RAW_IP_URL" in codes || "PDF_RAW_IP_URL" in codes || "OFFICE_RAW_IP_URL" in codes || "CLOUD_FLAGGED_URL" in codes) {
            findings += if (isId) {
                "tautan penipuan yang mengarah ke alamat mencurigakan"
            } else {
                "scam links pointing to a suspicious address"
            }
        }
        if ("APK_UNSIGNED" in codes) {
            findings += if (isId) {
                "aplikasi tak resmi tanpa tanda pengenal pengembang yang sah"
            } else {
                "an unofficial app without a valid developer signature"
            }
        }
        if ("CLOUD_REPUTATION_MALICIOUS" in codes || "CLOUD_REPUTATION_SUSPICIOUS" in codes) {
            findings += if (isId) {
                "file ini sudah dilaporkan sebagai penipuan atau program jahat"
            } else {
                "this file has been reported as a scam or harmful program"
            }
        }
        if ("ARCHIVE_CONTAINS_APK" in codes || "ARCHIVE_CONTAINS_EXECUTABLE" in codes) {
            findings += if (isId) {
                "aplikasi atau program tersembunyi di dalam arsip"
            } else {
                "a hidden app or program inside the archive"
            }
        }
        if ("ARCHIVE_PATH_TRAVERSAL" in codes || "ARCHIVE_ZIP_BOMB" in codes || "ARCHIVE_DOUBLE_EXTENSION" in codes) {
            findings += if (isId) {
                "struktur arsip yang dimanipulasi untuk menipu atau merusak perangkat"
            } else {
                "a manipulated archive designed to trick or overload your device"
            }
        }
        if ("PDF_JAVASCRIPT" in codes || "PDF_OPEN_ACTION" in codes || "PDF_LAUNCH_ACTION" in codes) {
            findings += if (isId) {
                "dokumen yang bisa menjalankan perintah otomatis saat dibuka"
            } else {
                "a document that can run automatic commands when opened"
            }
        }
        if ("OFFICE_MACRO" in codes || "OFFICE_MACRO_DETECTED" in codes || "OFFICE_REMOTE_TEMPLATE" in codes || "OFFICE_EXTERNAL_REL" in codes) {
            findings += if (isId) {
                "dokumen yang memuat skrip otomatis atau mengambil konten dari luar"
            } else {
                "a document with automatic scripts or external content links"
            }
        }
        if ("PARSE_FAILED" in codes || "ARCHIVE_UNSUPPORTED_INSPECTION" in codes) {
            findings += if (isId) {
                "isi file rusak atau tidak bisa diperiksa sepenuhnya"
            } else {
                "the file is damaged or its contents could not be fully checked"
            }
        }

        if (findings.isEmpty()) {
            return if (isId) {
                "Tidak ada tanda mencurigakan di dalam \"${report.fileName}\"."
            } else {
                "No suspicious contents were found inside \"${report.fileName}\"."
            }
        }

        val joined = findings.distinct().joinToString(if (isId) "; " else "; ")
        return if (isId) {
            "Di dalam \"${report.fileName}\" ditemukan: $joined."
        } else {
            "Inside \"${report.fileName}\" we found: $joined."
        }
    }

    private fun buildImpact(report: AnalysisReport, isId: Boolean): String {
        val codes = report.signals.map { it.code }.toSet()
        return if (isId) {
            when (report.verdict) {
                Verdict.BERBAHAYA -> when {
                    "APK_IMPERSONATION" in codes || "APK_SENSITIVE_PERMISSIONS" in codes ->
                        "Jika dipasang, pelaku bisa membaca kode OTP bank/e-wallet dan menguras saldo atau mengambil alih akun Anda. Hapus file ini dan jangan dipasang."
                    else ->
                        "Membuka file ini dapat membahayakan data pribadi, akun keuangan, atau perangkat Anda. Segera hapus dan abaikan pesan pengirimnya."
                }
                Verdict.MENCURIGAKAN ->
                    "File ini memiliki tanda yang tidak biasa atau tidak bisa diperiksa penuh. Jangan lanjutkan sebelum memastikan keasliannya langsung ke pengirim resmi."
                Verdict.AMAN ->
                    "Anda dapat menggunakan file ini seperti biasa, namun tetap waspada jika ada permintaan data pribadi."
            }
        } else {
            when (report.verdict) {
                Verdict.BERBAHAYA -> when {
                    "APK_IMPERSONATION" in codes || "APK_SENSITIVE_PERMISSIONS" in codes ->
                        "If installed, attackers may read your bank or e-wallet OTP codes and take over your accounts. Delete this file and do not install it."
                    else ->
                        "Opening this file may put your personal data, financial accounts, or device at risk. Delete it right away."
                }
                Verdict.MENCURIGAKAN ->
                    "This file has unusual signs or could not be fully checked. Verify directly with the official sender before opening."
                Verdict.AMAN ->
                    "You can use this file normally, though always stay alert if asked for personal information."
            }
        }
    }
}
