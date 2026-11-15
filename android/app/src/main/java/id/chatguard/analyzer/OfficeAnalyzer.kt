package id.chatguard.analyzer

import id.chatguard.core.model.FileType
import id.chatguard.core.model.Signal
import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import java.io.File
import java.util.Locale
import java.util.zip.ZipFile
import javax.xml.parsers.DocumentBuilderFactory

class OfficeAnalyzer : FileAnalyzer {

    override fun inspect(file: File): FileInspectionResult {
        val sha256 = AnalyzerSupport.sha256Hex(file)
        if (!file.exists() || !file.isFile || file.length() == 0L) {
            return AnalyzerSupport.parseFailed(file, FileType.OFFICE, sha256, "Office file missing or empty")
        }

        val signals = mutableListOf<Signal>()
        val extractedUrls = linkedSetOf<String>()
        var hasMacro = false
        var hasExternalRel = false
        var hasRemoteTemplate = false

        try {
            ZipFile(file).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val lower = entry.name.lowercase(Locale.ROOT)

                    if (!hasMacro && lower.endsWith("vbaproject.bin")) {
                        hasMacro = true
                        signals += Signal("OFFICE_MACRO", 40, "Office document contains VBA macro (${entry.name})")
                    }

                    if (lower.endsWith(".rels")) {
                        val relBytes = zip.getInputStream(entry).use {
                            AnalyzerSupport.readBounded(it, MAX_RELS_BYTES)
                        }
                        val rels = parseExternalRelationships(relBytes)
                        for (rel in rels) {
                            if (rel.target.startsWith("http://", ignoreCase = true) ||
                                rel.target.startsWith("https://", ignoreCase = true)
                            ) {
                                extractedUrls += rel.target
                            }
                            if (!hasExternalRel) {
                                hasExternalRel = true
                                signals += Signal("OFFICE_EXTERNAL_REL", 35, "External relationship target: ${rel.target}")
                            }
                            if (!hasRemoteTemplate && rel.type.contains("attachedTemplate", ignoreCase = true)) {
                                hasRemoteTemplate = true
                                signals += Signal("OFFICE_REMOTE_TEMPLATE", 45, "Remote template fetch: ${rel.target}")
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            return AnalyzerSupport.parseFailed(file, FileType.OFFICE, sha256, "Invalid Office ZIP container: ${e.message}")
        }

        val urls = extractedUrls.toList()
        if (urls.any { AnalyzerSupport.isRawIpUrl(it) }) {
            signals += Signal("OFFICE_RAW_IP_URL", 35, "Office document references raw IPv4 URL")
        }

        return FileInspectionResult(
            fileName = file.name,
            fileType = FileType.OFFICE,
            sha256 = sha256,
            extractedUrls = urls,
            signals = signals
        )
    }

    private data class ExternalRel(val type: String, val target: String)

    private fun parseExternalRelationships(xmlBytes: ByteArray): List<ExternalRel> {
        val results = mutableListOf<ExternalRel>()
        try {
            val factory = DocumentBuilderFactory.newInstance().apply {
                isNamespaceAware = false
                setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
                setFeature("http://xml.org/sax/features/external-general-entities", false)
                setFeature("http://xml.org/sax/features/external-parameter-entities", false)
                isExpandEntityReferences = false
            }
            val doc = factory.newDocumentBuilder().parse(ByteArrayInputStream(xmlBytes))
            val nodes = doc.getElementsByTagName("Relationship")
            for (i in 0 until nodes.length) {
                val el = nodes.item(i) as? Element ?: continue
                val targetMode = el.getAttribute("TargetMode")
                if (targetMode.equals("External", ignoreCase = true)) {
                    val target = el.getAttribute("Target").trim()
                    val type = el.getAttribute("Type").trim()
                    if (target.isNotEmpty()) {
                        results += ExternalRel(type = type, target = target)
                    }
                }
            }
        } catch (_: Exception) {
            // Ignore malformed individual .rels XML without crashing entire inspection
        }
        return results
    }

    companion object {
        private const val MAX_RELS_BYTES = 1024 * 1024
    }
}
