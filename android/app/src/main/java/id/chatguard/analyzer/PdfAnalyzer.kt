package id.chatguard.analyzer

import id.chatguard.core.model.FileType
import id.chatguard.core.model.Signal
import java.io.File

class PdfAnalyzer : FileAnalyzer {

    override fun inspect(file: File): FileInspectionResult {
        val sha256 = AnalyzerSupport.sha256Hex(file)
        if (!file.exists() || !file.isFile || file.length() < 5) {
            return AnalyzerSupport.parseFailed(file, FileType.PDF, sha256, "PDF file missing or too small")
        }

        val header = ByteArray(1024)
        val headerRead = try {
            file.inputStream().use { it.read(header) }
        } catch (e: Exception) {
            return AnalyzerSupport.parseFailed(file, FileType.PDF, sha256, "Unable to read PDF: ${e.message}")
        }
        val headerStr = String(header, 0, maxOf(0, headerRead), Charsets.ISO_8859_1)
        if (!headerStr.contains("%PDF-")) {
            return AnalyzerSupport.parseFailed(file, FileType.PDF, sha256, "Missing %PDF- header")
        }

        val extractedUrls = linkedSetOf<String>()
        var hasJavaScript = false
        var hasOpenAction = false
        var hasLaunch = false

        try {
            file.inputStream().use { input ->
                val chunk = ByteArray(CHUNK_SIZE)
                var carry = ""
                var totalScanned = 0L
                while (totalScanned < MAX_SCAN_BYTES) {
                    val read = input.read(chunk)
                    if (read <= 0) break
                    totalScanned += read
                    val window = carry + String(chunk, 0, read, Charsets.ISO_8859_1)

                    if (!hasJavaScript && (JS_TOKEN_REGEX.containsMatchIn(window))) {
                        hasJavaScript = true
                    }
                    if (!hasOpenAction && window.contains("/OpenAction")) {
                        hasOpenAction = true
                    }
                    if (!hasLaunch && LAUNCH_TOKEN_REGEX.containsMatchIn(window)) {
                        hasLaunch = true
                    }

                    for (match in PDF_URI_REGEX.findAll(window)) {
                        val candidate = match.groupValues[1].trim()
                        if (candidate.startsWith("http://", ignoreCase = true) ||
                            candidate.startsWith("https://", ignoreCase = true)
                        ) {
                            extractedUrls += candidate
                        }
                    }
                    extractedUrls += AnalyzerSupport.extractHttpUrls(window)

                    carry = if (window.length > OVERLAP_SIZE) {
                        window.substring(window.length - OVERLAP_SIZE)
                    } else {
                        window
                    }
                }
            }
        } catch (e: Exception) {
            return AnalyzerSupport.parseFailed(file, FileType.PDF, sha256, "PDF scan failed: ${e.message}")
        }

        val signals = mutableListOf<Signal>()
        if (hasJavaScript) {
            signals += Signal("PDF_JAVASCRIPT", 45, "PDF contains embedded JavaScript (/JavaScript or /JS)")
        }
        if (hasOpenAction) {
            signals += Signal("PDF_OPEN_ACTION", 30, "PDF defines automatic /OpenAction")
        }
        if (hasLaunch) {
            signals += Signal("PDF_LAUNCH_ACTION", 50, "PDF contains /Launch action")
        }
        val urls = extractedUrls.toList()
        if (urls.any { AnalyzerSupport.isRawIpUrl(it) }) {
            signals += Signal("PDF_RAW_IP_URL", 35, "PDF contains raw IPv4 URL")
        }

        return FileInspectionResult(
            fileName = file.name,
            fileType = FileType.PDF,
            sha256 = sha256,
            extractedUrls = urls,
            signals = signals
        )
    }

    companion object {
        private const val CHUNK_SIZE = 65_536
        private const val OVERLAP_SIZE = 1024
        private const val MAX_SCAN_BYTES = 16L * 1024L * 1024L
        private val JS_TOKEN_REGEX = Regex("""/(?:JavaScript|JS)\b""")
        private val LAUNCH_TOKEN_REGEX = Regex("""/Launch\b""")
        private val PDF_URI_REGEX = Regex("""/URI\s*\(([^)\r\n]+)\)""")
    }
}
