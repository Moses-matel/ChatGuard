package id.chatguard.stage1

import id.chatguard.core.model.NotificationAlert
import id.chatguard.core.model.Verdict

/**
 * Pre-download notification analyzer inspecting incoming messaging notifications
 * for suspicious file attachments, double extensions, and phishing lure indicators.
 *
 * Privacy guarantee: Never persists or logs raw message contents to disk or network.
 */
class NotificationAnalyzer {

    @JvmOverloads
    fun analyze(
        packageName: String,
        title: String,
        text: String,
        returnCleanAlert: Boolean = false
    ): NotificationAlert? {
        return Companion.analyze(packageName, title, text, returnCleanAlert)
    }

    companion object {
        val SUPPORTED_PACKAGES = setOf(
            "com.whatsapp",
            "com.whatsapp.w4b",
            "org.telegram.messenger"
        )

        val LURE_KEYWORDS = listOf(
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

        private val LURE_KEYWORD_REGEXES = LURE_KEYWORDS.map { keyword ->
            Regex("""\b$keyword\b""", RegexOption.IGNORE_CASE)
        }

        private const val DOUBLE_EXT_PREFIXES =
            "(?:pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|bmp|webp|mp[34]|wav|mkv|zip|rar|7z|tar|gz)"

        private val DOUBLE_EXT_APK_REGEX = Regex(
            """(?i)(?:^|[\r\n:📄\t]|[^\w\s\-.,&()\[\]])\s*([a-zA-Z0-9_\-.,&()\[\]]+(?:\s+[a-zA-Z0-9_\-.,&()\[\]]+)*\.$DOUBLE_EXT_PREFIXES\.apk)(?=$|[\s()\[\]—–-]|\b)"""
        )

        private val APK_REGEX = Regex(
            """(?i)(?:^|[\r\n:📄\t]|[^\w\s\-.,&()\[\]])\s*([a-zA-Z0-9_\-.,&()\[\]]+(?:\s+[a-zA-Z0-9_\-.,&()\[\]]+)*\.apk)(?=$|[\s()\[\]—–-]|\b)"""
        )

        private val RISKY_EXEC_REGEX = Regex(
            """(?i)(?:^|[\r\n:📄\t]|[^\w\s\-.,&()\[\]])\s*([a-zA-Z0-9_\-.,&()\[\]]+(?:\s+[a-zA-Z0-9_\-.,&()\[\]]+)*\.(?:exe|bat|cmd|vbs|js|scr))(?=$|[\s()\[\]—–-]|\b)"""
        )

        private val DOC_REGEX = Regex(
            """(?i)(?:^|[\r\n:📄\t]|[^\w\s\-.,&()\[\]])\s*([a-zA-Z0-9_\-.,&()\[\]]+(?:\s+[a-zA-Z0-9_\-.,&()\[\]]+)*\.(?:pdf|docx?|xlsx?|pptx?|zip|rar|7z|tar|gz|txt|csv))(?=$|[\s()\[\]—–-]|\b)"""
        )

        private val MEDIA_REGEX = Regex(
            """(?i)(?:^|[\r\n:📄\t]|[^\w\s\-.,&()\[\]])\s*([a-zA-Z0-9_\-.,&()\[\]]+(?:\s+[a-zA-Z0-9_\-.,&()\[\]]+)*\.(?:jpe?g|png|gif|bmp|webp|mp[34]|wav|mkv))(?=$|[\s()\[\]—–-]|\b)"""
        )

        private data class FileCandidate(
            val fileName: String,
            val isDoubleExtApk: Boolean,
            val isApk: Boolean,
            val isRiskyExecutable: Boolean,
            val isDocumentOrArchive: Boolean
        )

        private fun findFileCandidate(content: String): FileCandidate? {
            if (content.isBlank()) return null

            // 1. Double extension APK (highest priority)
            DOUBLE_EXT_APK_REGEX.find(content)?.let { match ->
                val name = match.groupValues[1].trim().trimEnd('.', ',', ';')
                return FileCandidate(
                    fileName = name,
                    isDoubleExtApk = true,
                    isApk = true,
                    isRiskyExecutable = false,
                    isDocumentOrArchive = false
                )
            }

            // 2. Risky executables
            RISKY_EXEC_REGEX.find(content)?.let { match ->
                val name = match.groupValues[1].trim().trimEnd('.', ',', ';')
                return FileCandidate(
                    fileName = name,
                    isDoubleExtApk = false,
                    isApk = false,
                    isRiskyExecutable = true,
                    isDocumentOrArchive = false
                )
            }

            // 3. Single APK
            APK_REGEX.find(content)?.let { match ->
                val name = match.groupValues[1].trim().trimEnd('.', ',', ';')
                return FileCandidate(
                    fileName = name,
                    isDoubleExtApk = false,
                    isApk = true,
                    isRiskyExecutable = false,
                    isDocumentOrArchive = false
                )
            }

            // 4. Documents & Archives
            DOC_REGEX.find(content)?.let { match ->
                val name = match.groupValues[1].trim().trimEnd('.', ',', ';')
                return FileCandidate(
                    fileName = name,
                    isDoubleExtApk = false,
                    isApk = false,
                    isRiskyExecutable = false,
                    isDocumentOrArchive = true
                )
            }

            // 5. Media & Images
            MEDIA_REGEX.find(content)?.let { match ->
                val name = match.groupValues[1].trim().trimEnd('.', ',', ';')
                return FileCandidate(
                    fileName = name,
                    isDoubleExtApk = false,
                    isApk = false,
                    isRiskyExecutable = false,
                    isDocumentOrArchive = false
                )
            }

            return null
        }

        private fun hasLureKeyword(vararg texts: String): Boolean {
            val normalized = texts.joinToString(" ").replace(Regex("""[^a-zA-Z0-9]"""), " ")
            return LURE_KEYWORD_REGEXES.any { regex -> regex.containsMatchIn(normalized) }
        }

        @JvmOverloads
        fun analyze(
            packageName: String,
            title: String,
            text: String,
            returnCleanAlert: Boolean = false
        ): NotificationAlert? {
            // Requirement 1: Only supported messaging packages
            if (packageName.lowercase() !in SUPPORTED_PACKAGES) {
                return null
            }

            // Find file clues in text first, then title
            val candidate = findFileCandidate(text) ?: findFileCandidate(title) ?: return null

            val hasLure = hasLureKeyword(candidate.fileName, title, text)
            val reasons = mutableListOf<String>()
            val verdict: Verdict

            when {
                candidate.isDoubleExtApk -> {
                    verdict = Verdict.BERBAHAYA
                    reasons.add("DOUBLE_EXTENSION_APK")
                    reasons.add("APK_VIA_CHAT")
                    if (hasLure) {
                        reasons.add("LURE_KEYWORDS_ID")
                    }
                }
                candidate.isRiskyExecutable -> {
                    verdict = Verdict.BERBAHAYA
                    reasons.add("RISKY_EXECUTABLE_EXTENSION")
                    if (hasLure) {
                        reasons.add("LURE_KEYWORDS_ID")
                    }
                }
                candidate.isApk -> {
                    reasons.add("APK_VIA_CHAT")
                    if (hasLure) {
                        verdict = Verdict.BERBAHAYA
                        reasons.add("LURE_KEYWORDS_ID")
                    } else {
                        verdict = Verdict.MENCURIGAKAN
                    }
                }
                hasLure -> {
                    verdict = Verdict.MENCURIGAKAN
                    reasons.add("LURE_KEYWORDS_ID")
                }
                else -> {
                    verdict = Verdict.AMAN
                }
            }

            if (verdict == Verdict.AMAN && !returnCleanAlert) {
                return null
            }

            return NotificationAlert(
                sourcePackage = packageName,
                sender = title.trim().ifBlank { "Unknown" },
                fileName = candidate.fileName,
                verdict = verdict,
                reasons = reasons
            )
        }
    }
}
