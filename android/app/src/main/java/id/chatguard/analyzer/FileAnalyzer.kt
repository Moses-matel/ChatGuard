package id.chatguard.analyzer

import id.chatguard.core.model.FileType
import id.chatguard.core.model.Signal
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.ZipFile

data class FileInspectionResult(
    val fileName: String,
    val fileType: FileType,
    val sha256: String,
    val packageName: String? = null,
    val certSha256: String? = null,
    val permissions: List<String> = emptyList(),
    val extractedUrls: List<String> = emptyList(),
    val signals: List<Signal> = emptyList(),
    val parseFailed: Boolean = false
)

interface FileAnalyzer {
    fun inspect(file: File): FileInspectionResult
}

object FileAnalyzerDispatcher {
    private val apkAnalyzer = ApkAnalyzer()
    private val pdfAnalyzer = PdfAnalyzer()
    private val officeAnalyzer = OfficeAnalyzer()
    private val archiveAnalyzer = ArchiveAnalyzer()

    fun inspect(file: File): FileInspectionResult {
        return when (detectFileType(file)) {
            FileType.APK -> apkAnalyzer.inspect(file)
            FileType.PDF -> pdfAnalyzer.inspect(file)
            FileType.OFFICE -> officeAnalyzer.inspect(file)
            FileType.ARCHIVE -> archiveAnalyzer.inspect(file)
            FileType.UNKNOWN -> FileInspectionResult(
                fileName = file.name,
                fileType = FileType.UNKNOWN,
                sha256 = AnalyzerSupport.sha256Hex(file)
            )
        }
    }

    fun detectFileType(file: File): FileType {
        val ext = file.name.substringAfterLast('.', "").lowercase(Locale.ROOT)
        when (ext) {
            "apk" -> return FileType.APK
            "pdf" -> return FileType.PDF
            "docx", "xlsx", "docm", "xlsm" -> return FileType.OFFICE
            "zip", "rar" -> return FileType.ARCHIVE
        }

        if (!file.exists() || !file.isFile) return FileType.UNKNOWN
        val header = ByteArray(8)
        val read = try {
            file.inputStream().use { it.read(header) }
        } catch (_: Exception) {
            -1
        }
        if (read >= 5 && header[0] == '%'.code.toByte() && header[1] == 'P'.code.toByte() &&
            header[2] == 'D'.code.toByte() && header[3] == 'F'.code.toByte() && header[4] == '-'.code.toByte()
        ) {
            return FileType.PDF
        }
        if (read >= 4 && header[0] == 0x52.toByte() && header[1] == 0x61.toByte() &&
            header[2] == 0x72.toByte() && header[3] == 0x21.toByte()
        ) {
            return FileType.ARCHIVE
        }
        if (read >= 4 && header[0] == 0x50.toByte() && header[1] == 0x4B.toByte() &&
            header[2] == 0x03.toByte() && header[3] == 0x04.toByte()
        ) {
            return try {
                ZipFile(file).use { zip ->
                    when {
                        zip.getEntry("AndroidManifest.xml") != null -> FileType.APK
                        zip.getEntry("[Content_Types].xml") != null -> FileType.OFFICE
                        else -> FileType.ARCHIVE
                    }
                }
            } catch (_: Exception) {
                FileType.ARCHIVE
            }
        }
        return FileType.UNKNOWN
    }
}

internal object AnalyzerSupport {
    private val URL_REGEX = Regex("""https?://[^\s"'<>()\[\]{}]+""", RegexOption.IGNORE_CASE)
    private val RAW_IP_URL_REGEX = Regex("""^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)""", RegexOption.IGNORE_CASE)

    fun sha256Hex(file: File): String {
        return sha256HexOrNull(file) ?: ""
    }

    fun sha256HexOrNull(file: File): String? {
        if (!file.exists() || !file.isFile) return null
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(8192)
                while (true) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    digest.update(buffer, 0, read)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            null
        }
    }

    fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(bytes).joinToString("") { "%02x".format(it) }
    }

    fun readBounded(input: InputStream, maxBytes: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0
        while (total < maxBytes) {
            val toRead = minOf(buf.size, maxBytes - total)
            val read = input.read(buf, 0, toRead)
            if (read <= 0) break
            out.write(buf, 0, read)
            total += read
        }
        return out.toByteArray()
    }

    fun extractHttpUrls(text: String): List<String> {
        return URL_REGEX.findAll(text)
            .map { it.value.trimEnd('.', ',', ';', ')', '\'', '"') }
            .filter { it.length > 8 }
            .distinct()
            .toList()
    }

    fun isRawIpUrl(url: String): Boolean = RAW_IP_URL_REGEX.containsMatchIn(url)

    fun parseFailed(file: File, fileType: FileType, sha256: String, reason: String): FileInspectionResult {
        return FileInspectionResult(
            fileName = file.name,
            fileType = fileType,
            sha256 = sha256,
            signals = listOf(Signal("PARSE_FAILED", 20, reason)),
            parseFailed = true
        )
    }
}
