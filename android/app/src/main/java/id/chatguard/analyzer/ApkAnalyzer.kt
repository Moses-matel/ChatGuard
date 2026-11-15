package id.chatguard.analyzer

import android.content.Context
import id.chatguard.core.model.FileType
import id.chatguard.core.model.Signal
import java.io.ByteArrayInputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.zip.ZipFile

class ApkAnalyzer(private val context: Context? = null) : FileAnalyzer {

    override fun inspect(file: File): FileInspectionResult {
        val sha256 = AnalyzerSupport.sha256Hex(file)
        if (!file.exists() || !file.isFile || file.length() < 22) {
            return AnalyzerSupport.parseFailed(file, FileType.APK, sha256, "APK file missing or truncated")
        }

        var packageName: String?
        val permissions = linkedSetOf<String>()
        val extractedUrls = linkedSetOf<String>()
        var certSha256: String? = null

        try {
            ZipFile(file).use { zip ->
                val manifestEntry = zip.getEntry("AndroidManifest.xml")
                    ?: return AnalyzerSupport.parseFailed(file, FileType.APK, sha256, "Missing AndroidManifest.xml")

                val manifestBytes = zip.getInputStream(manifestEntry).use {
                    AnalyzerSupport.readBounded(it, MAX_MANIFEST_BYTES)
                }
                val parsedManifest = parseBinaryAxml(manifestBytes)
                packageName = parsedManifest.packageName
                permissions += parsedManifest.permissions

                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val name = entry.name
                    val lower = name.lowercase(Locale.ROOT)

                    if (certSha256 == null && lower.startsWith("meta-inf/") &&
                        (lower.endsWith(".rsa") || lower.endsWith(".dsa") || lower.endsWith(".ec"))
                    ) {
                        val certBytes = zip.getInputStream(entry).use {
                            AnalyzerSupport.readBounded(it, MAX_CERT_BYTES)
                        }
                        certSha256 = extractCertSha256(certBytes)
                    }

                    if ((lower.startsWith("classes") && lower.endsWith(".dex")) || lower == "resources.arsc") {
                        zip.getInputStream(entry).use { stream ->
                            scanStreamForUrls(stream, extractedUrls)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            return AnalyzerSupport.parseFailed(file, FileType.APK, sha256, "Corrupted APK archive: ${e.message}")
        }

        if (certSha256 == null) {
            certSha256 = extractV2V3CertSha256(file)
        }

        if ((packageName == null || permissions.isEmpty()) && context != null) {
            val pmInfo = tryReadWithPackageManager(context, file)
            if (packageName == null) packageName = pmInfo.first
            if (permissions.isEmpty()) permissions += pmInfo.second
        }

        val urls = extractedUrls.toList()
        val signals = mutableListOf<Signal>()
        if (urls.any { AnalyzerSupport.isRawIpUrl(it) }) {
            signals += Signal("APK_RAW_IP_URL", 40, "APK contains raw IPv4 URL")
        }
        val sensitivePerms = permissions.filter { it in SENSITIVE_PERMISSIONS }
        if (sensitivePerms.isNotEmpty()) {
            signals += Signal(
                "APK_SENSITIVE_PERMISSIONS",
                35,
                "Requests sensitive permissions: ${sensitivePerms.joinToString(", ")}"
            )
        }
        if (certSha256 == null) {
            signals += Signal("APK_UNSIGNED", 30, "No signing certificate found")
        }

        return FileInspectionResult(
            fileName = file.name,
            fileType = FileType.APK,
            sha256 = sha256,
            packageName = packageName,
            certSha256 = certSha256,
            permissions = permissions.toList(),
            extractedUrls = urls,
            signals = signals
        )
    }

    private fun scanStreamForUrls(stream: java.io.InputStream, out: MutableSet<String>) {
        val buf = ByteArray(65_536)
        var carry = ""
        var total = 0L
        while (total < MAX_DEX_SCAN_BYTES) {
            val read = stream.read(buf)
            if (read <= 0) break
            total += read
            val window = carry + String(buf, 0, read, Charsets.ISO_8859_1)
            out += AnalyzerSupport.extractHttpUrls(window)
            carry = if (window.length > 512) window.substring(window.length - 512) else window
        }
    }

    private fun extractCertSha256(certBytes: ByteArray): String? {
        if (certBytes.isEmpty()) return null
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val certs = cf.generateCertificates(ByteArrayInputStream(certBytes))
            val first = certs.firstOrNull() as? X509Certificate
            if (first != null) {
                AnalyzerSupport.sha256Hex(first.encoded)
            } else {
                AnalyzerSupport.sha256Hex(certBytes)
            }
        } catch (_: Exception) {
            AnalyzerSupport.sha256Hex(certBytes)
        }
    }

    private fun extractV2V3CertSha256(file: File): String? {
        return try {
            RandomAccessFile(file, "r").use { raf ->
                val len = raf.length()
                if (len < 32) return null
                // Locate End of Central Directory (0x06054b50) in last 64KB
                val searchSize = minOf(len, 65_557L).toInt()
                val tail = ByteArray(searchSize)
                raf.seek(len - searchSize)
                raf.readFully(tail)
                var eocdOffset = -1
                for (i in searchSize - 22 downTo 0) {
                    if (tail[i] == 0x50.toByte() && tail[i + 1] == 0x4B.toByte() &&
                        tail[i + 2] == 0x05.toByte() && tail[i + 3] == 0x06.toByte()
                    ) {
                        eocdOffset = i
                        break
                    }
                }
                if (eocdOffset < 0) return null
                val cdOffset = ByteBuffer.wrap(tail, eocdOffset + 16, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                if (cdOffset < 24 || cdOffset > len) return null

                // Check for "APK Sig Block 42" at cdOffset - 16
                val magicBuf = ByteArray(16)
                raf.seek(cdOffset - 16)
                raf.readFully(magicBuf)
                if (String(magicBuf, Charsets.US_ASCII) != "APK Sig Block 42") return null

                val sizeBuf = ByteArray(8)
                raf.seek(cdOffset - 24)
                raf.readFully(sizeBuf)
                val blockSize = ByteBuffer.wrap(sizeBuf).order(ByteOrder.LITTLE_ENDIAN).long
                if (blockSize < 24 || blockSize > cdOffset || blockSize > MAX_SIG_BLOCK_BYTES) return null

                val blockStart = cdOffset - blockSize - 8
                if (blockStart < 0) return null
                val block = ByteArray(blockSize.toInt())
                raf.seek(blockStart + 8)
                raf.readFully(block)

                // Find first X.509 certificate sequence (0x30 0x82) inside v2/v3 block
                val cf = CertificateFactory.getInstance("X.509")
                for (i in 0 until block.size - 4) {
                    if (block[i] == 0x30.toByte() && block[i + 1] == 0x82.toByte()) {
                        val certLen = ((block[i + 2].toInt() and 0xFF) shl 8) or (block[i + 3].toInt() and 0xFF) + 4
                        if (certLen in 200..16_384 && i + certLen <= block.size) {
                            try {
                                val cert = cf.generateCertificate(ByteArrayInputStream(block, i, certLen)) as? X509Certificate
                                if (cert != null) {
                                    return AnalyzerSupport.sha256Hex(cert.encoded)
                                }
                            } catch (_: Exception) {
                                // Continue scanning
                            }
                        }
                    }
                }
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    @Suppress("DEPRECATION")
    private fun tryReadWithPackageManager(ctx: Context, file: File): Pair<String?, List<String>> {
        return try {
            val pm = ctx.packageManager
            val info = pm.getPackageArchiveInfo(file.absolutePath, android.content.pm.PackageManager.GET_PERMISSIONS)
            val pkg = info?.packageName
            val perms = info?.requestedPermissions?.toList() ?: emptyList()
            pkg to perms
        } catch (_: Exception) {
            null to emptyList()
        }
    }

    private data class ParsedManifest(val packageName: String?, val permissions: List<String>)

    private fun parseBinaryAxml(bytes: ByteArray): ParsedManifest {
        if (bytes.size < 8) return ParsedManifest(null, emptyList())
        val bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val fileType = bb.getShort(0).toInt() and 0xFFFF
        if (fileType != 0x0003) {
            return parsePlainTextManifest(bytes)
        }

        var pos = bb.getShort(2).toInt() and 0xFFFF
        var strings: List<String> = emptyList()
        var packageName: String? = null
        val permissions = linkedSetOf<String>()

        while (pos + 8 <= bytes.size) {
            val chunkType = bb.getShort(pos).toInt() and 0xFFFF
            val chunkHeaderSize = bb.getShort(pos + 2).toInt() and 0xFFFF
            val chunkSize = bb.getInt(pos + 4)
            if (chunkSize < 8 || pos + chunkSize > bytes.size) break

            when (chunkType) {
                0x0001 -> {
                    strings = parseStringPool(bytes, pos, chunkHeaderSize, chunkSize)
                }
                0x0102 -> {
                    if (pos + 36 <= bytes.size) {
                        val nameIdx = bb.getInt(pos + 20)
                        val attrStartOffset = 16 + (bb.getShort(pos + 24).toInt() and 0xFFFF)
                        val attrSize = bb.getShort(pos + 26).toInt() and 0xFFFF
                        val attrCount = bb.getShort(pos + 28).toInt() and 0xFFFF
                        val tagName = strings.getOrNull(nameIdx)

                        if (attrSize >= 20) {
                            for (i in 0 until attrCount) {
                                val attrPos = pos + attrStartOffset + i * attrSize
                                if (attrPos + 20 > pos + chunkSize) break
                                val attrNameIdx = bb.getInt(attrPos + 4)
                                val rawValueIdx = bb.getInt(attrPos + 8)
                                val dataType = bytes[attrPos + 15].toInt() and 0xFF
                                val data = bb.getInt(attrPos + 16)
                                val attrName = strings.getOrNull(attrNameIdx)
                                val value = when {
                                    rawValueIdx in strings.indices -> strings[rawValueIdx]
                                    dataType == 0x03 && data in strings.indices -> strings[data]
                                    else -> null
                                }

                                if (tagName == "manifest" && attrName == "package" && !value.isNullOrBlank()) {
                                    packageName = value
                                } else if (tagName == "uses-permission" && attrName == "name" && !value.isNullOrBlank()) {
                                    permissions += value
                                }
                            }
                        }
                    }
                }
            }
            pos += chunkSize
        }

        return ParsedManifest(packageName, permissions.toList())
    }

    private fun parseStringPool(bytes: ByteArray, chunkStart: Int, headerSize: Int, chunkSize: Int): List<String> {
        if (chunkStart + 28 > bytes.size) return emptyList()
        val bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val stringCount = bb.getInt(chunkStart + 8)
        val flags = bb.getInt(chunkStart + 16)
        val stringsStart = bb.getInt(chunkStart + 20)
        val isUtf8 = (flags and 0x0100) != 0

        if (stringCount <= 0 || stringCount > 100_000) return emptyList()
        val offsetsBase = chunkStart + headerSize
        val dataBase = chunkStart + stringsStart
        if (offsetsBase + stringCount * 4 > chunkStart + chunkSize) return emptyList()

        val result = ArrayList<String>(stringCount)
        for (i in 0 until stringCount) {
            val relOff = bb.getInt(offsetsBase + i * 4)
            val strPos = dataBase + relOff
            if (strPos < dataBase || strPos >= chunkStart + chunkSize) {
                result += ""
                continue
            }
            result += if (isUtf8) {
                readUtf8String(bytes, strPos, chunkStart + chunkSize)
            } else {
                readUtf16String(bytes, strPos, chunkStart + chunkSize)
            }
        }
        return result
    }

    private fun readUtf8String(bytes: ByteArray, start: Int, limit: Int): String {
        var p = start
        if (p >= limit) return ""
        // Skip UTF-16 char length (1 or 2 bytes)
        val c1 = bytes[p++].toInt() and 0xFF
        if ((c1 and 0x80) != 0 && p < limit) p++
        if (p >= limit) return ""
        var byteLen = bytes[p++].toInt() and 0xFF
        if ((byteLen and 0x80) != 0 && p < limit) {
            byteLen = ((byteLen and 0x7F) shl 8) or (bytes[p++].toInt() and 0xFF)
        }
        val safeLen = minOf(byteLen, maxOf(0, limit - p))
        return String(bytes, p, safeLen, Charsets.UTF_8)
    }

    private fun readUtf16String(bytes: ByteArray, start: Int, limit: Int): String {
        if (start + 2 > limit) return ""
        val bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        var p = start
        var charLen = bb.getShort(p).toInt() and 0xFFFF
        p += 2
        if ((charLen and 0x8000) != 0) {
            if (p + 2 > limit) return ""
            charLen = ((charLen and 0x7FFF) shl 16) or (bb.getShort(p).toInt() and 0xFFFF)
            p += 2
        }
        val byteLen = minOf(charLen * 2, maxOf(0, limit - p))
        return String(bytes, p, byteLen, Charsets.UTF_16LE)
    }

    private fun parsePlainTextManifest(bytes: ByteArray): ParsedManifest {
        val text = String(bytes, Charsets.UTF_8)
        val pkg = Regex("""package\s*=\s*["']([^"']+)["']""").find(text)?.groupValues?.get(1)
        val perms = Regex("""android\.permission\.[A-Z0-9_]+""").findAll(text).map { it.value }.distinct().toList()
        return ParsedManifest(pkg, perms)
    }

    companion object {
        private const val MAX_MANIFEST_BYTES = 4 * 1024 * 1024
        private const val MAX_CERT_BYTES = 1024 * 1024
        private const val MAX_DEX_SCAN_BYTES = 16L * 1024L * 1024L
        private const val MAX_SIG_BLOCK_BYTES = 8L * 1024L * 1024L

        private val SENSITIVE_PERMISSIONS = setOf(
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG"
        )
    }
}
