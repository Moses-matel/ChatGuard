package id.chatguard.analyzer

import id.chatguard.core.model.FileType
import id.chatguard.core.model.Signal
import java.io.File
import java.util.Locale
import java.util.zip.ZipFile

class ArchiveAnalyzer : FileAnalyzer {

    override fun inspect(file: File): FileInspectionResult {
        val sha256 = AnalyzerSupport.sha256Hex(file)
        if (!file.exists() || !file.isFile || file.length() == 0L) {
            return AnalyzerSupport.parseFailed(file, FileType.ARCHIVE, sha256, "Archive file missing or empty")
        }

        val magic = ByteArray(8)
        val read = try {
            file.inputStream().use { it.read(magic) }
        } catch (e: Exception) {
            return AnalyzerSupport.parseFailed(file, FileType.ARCHIVE, sha256, "Unable to read archive: ${e.message}")
        }

        val isZip = read >= 4 &&
            magic[0] == 0x50.toByte() && magic[1] == 0x4B.toByte() &&
            magic[2] == 0x03.toByte() && magic[3] == 0x04.toByte()

        if (isZip) {
            return inspectZip(file, sha256)
        }

        val isRar = read >= 4 &&
            magic[0] == 0x52.toByte() && magic[1] == 0x61.toByte() &&
            magic[2] == 0x72.toByte() && magic[3] == 0x21.toByte()

        if (isRar || file.extension.lowercase(Locale.ROOT) == "rar") {
            return inspectRar(file, sha256, magic, read)
        }

        return AnalyzerSupport.parseFailed(file, FileType.ARCHIVE, sha256, "Unrecognized archive format")
    }

    private fun inspectZip(file: File, sha256: String): FileInspectionResult {
        val signals = mutableListOf<Signal>()
        var hasTraversal = false
        var hasZipBomb = false
        var hasApk = false
        var hasExecutable = false
        var hasDoubleExt = false
        var entryCount = 0
        var totalUncompressed = 0L

        try {
            ZipFile(file).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    entryCount++

                    val name = entry.name
                    val normalized = name.replace('\\', '/')
                    if (!hasTraversal && (normalized.startsWith("/") || normalized.split('/').any { it == ".." })) {
                        hasTraversal = true
                        signals += Signal("ARCHIVE_PATH_TRAVERSAL", 40, "Path traversal entry: $name")
                    }

                    val size = entry.size
                    if (size > 0) {
                        totalUncompressed += size
                    }
                    if (!hasZipBomb && (size > MAX_UNCOMPRESSED_BYTES || totalUncompressed > MAX_UNCOMPRESSED_BYTES || entryCount > MAX_ENTRY_COUNT)) {
                        hasZipBomb = true
                        signals += Signal(
                            "ARCHIVE_ZIP_BOMB",
                            50,
                            "Archive exceeds safe limits (entries=$entryCount, totalBytes=$totalUncompressed)"
                        )
                    }

                    val baseName = normalized.substringAfterLast('/')
                    val lower = baseName.lowercase(Locale.ROOT)
                    if (!hasApk && lower.endsWith(".apk")) {
                        hasApk = true
                        signals += Signal("ARCHIVE_CONTAINS_APK", 45, "Archive contains APK: $baseName")
                    }
                    if (!hasExecutable && EXECUTABLE_EXTENSIONS.any { lower.endsWith(".$it") }) {
                        hasExecutable = true
                        signals += Signal("ARCHIVE_CONTAINS_EXECUTABLE", 45, "Archive contains executable: $baseName")
                    }
                    if (!hasDoubleExt && isDoubleExtension(lower)) {
                        hasDoubleExt = true
                        signals += Signal("ARCHIVE_DOUBLE_EXTENSION", 35, "Double extension entry: $baseName")
                    }
                }
            }
        } catch (e: Exception) {
            return AnalyzerSupport.parseFailed(file, FileType.ARCHIVE, sha256, "Corrupted ZIP archive: ${e.message}")
        }

        return FileInspectionResult(
            fileName = file.name,
            fileType = FileType.ARCHIVE,
            sha256 = sha256,
            signals = signals
        )
    }

    private fun inspectRar(file: File, sha256: String, magic: ByteArray, read: Int): FileInspectionResult {
        // RAR5 magic: 52 61 72 21 1A 07 01 00; RAR4 magic: 52 61 72 21 1A 07 00
        val isRarMagic = read >= 7 &&
            magic[0] == 0x52.toByte() && magic[1] == 0x61.toByte() &&
            magic[2] == 0x72.toByte() && magic[3] == 0x21.toByte() &&
            magic[4] == 0x1A.toByte() && magic[5] == 0x07.toByte()

        if (!isRarMagic) {
            return AnalyzerSupport.parseFailed(file, FileType.ARCHIVE, sha256, "Invalid RAR header")
        }

        return FileInspectionResult(
            fileName = file.name,
            fileType = FileType.ARCHIVE,
            sha256 = sha256,
            signals = listOf(
                Signal(
                    "ARCHIVE_UNSUPPORTED_INSPECTION",
                    25,
                    "RAR archive contents cannot be fully inspected on-device"
                )
            )
        )
    }

    private fun isDoubleExtension(lowerName: String): Boolean {
        val parts = lowerName.split('.').filter { it.isNotEmpty() }
        if (parts.size < 3) return false
        val last = parts.last()
        val prev = parts[parts.size - 2]
        val dangerousLast = last == "apk" || last in EXECUTABLE_EXTENSIONS
        val decoyPrev = prev in DECOY_EXTENSIONS
        return dangerousLast && decoyPrev
    }

    companion object {
        const val MAX_UNCOMPRESSED_BYTES = 500_000_000L
        const val MAX_ENTRY_COUNT = 10_000
        private val EXECUTABLE_EXTENSIONS = setOf("exe", "bat", "cmd", "js", "vbs", "scr")
        private val DECOY_EXTENSIONS = setOf("pdf", "jpg", "jpeg", "png", "doc", "docx", "xls", "xlsx", "txt")
    }
}
