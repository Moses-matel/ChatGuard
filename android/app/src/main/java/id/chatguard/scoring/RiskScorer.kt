package id.chatguard.scoring

import id.chatguard.analyzer.FileInspectionResult
import id.chatguard.core.model.AnalysisReport
import id.chatguard.core.model.FileType
import id.chatguard.core.model.OfficialAppEntry
import id.chatguard.core.model.ReputationResponse
import id.chatguard.core.model.Signal
import id.chatguard.core.model.Verdict

object RiskScorer {
    private const val THRESHOLD_BERBAHAYA = 70
    private const val THRESHOLD_MENCURIGAKAN = 35

    private val SENSITIVE_PERMISSION_NAMES = setOf(
        "READ_SMS",
        "RECEIVE_SMS",
        "READ_CONTACTS",
        "BIND_NOTIFICATION_LISTENER_SERVICE"
    )

    private val NON_CORROBORATING_CODES = setOf(
        "APK_SENSITIVE_PERMISSIONS",
        "CHAT_SIDELOAD_APK",
        "OFFICIAL_APP_VERIFIED"
    )

    private val CRITICAL_DANGEROUS_CODES = setOf(
        "APK_IMPERSONATION",
        "CLOUD_REPUTATION_MALICIOUS",
        "ARCHIVE_PATH_TRAVERSAL",
        "ARCHIVE_ZIP_BOMB",
        "ARCHIVE_CONTAINS_APK",
        "ARCHIVE_CONTAINS_EXECUTABLE"
    )

    fun evaluate(
        inspection: FileInspectionResult,
        reputation: ReputationResponse?,
        allowlist: Map<String, OfficialAppEntry>,
        fromChat: Boolean = true
    ): AnalysisReport {
        val isCloudMalicious = reputation?.verdict?.equals("malicious", ignoreCase = true) == true
        val isCloudSuspicious = reputation?.verdict?.equals("suspicious", ignoreCase = true) == true
        val hasFlaggedUrls = !reputation?.flaggedUrls.isNullOrEmpty()

        val pkg = inspection.packageName
        val officialEntry = pkg?.let { allowlist[it] }
        val allowlistCertMatch = officialEntry != null &&
            inspection.certSha256 != null &&
            inspection.certSha256.equals(officialEntry.certSha256, ignoreCase = true)
        val cloudCertMatch = reputation?.officialCertMatch == true
        val isOfficialMatch = inspection.fileType == FileType.APK && (allowlistCertMatch || cloudCertMatch)

        if (isOfficialMatch && !isCloudMalicious) {
            return AnalysisReport(
                fileName = inspection.fileName,
                fileType = inspection.fileType,
                sha256 = inspection.sha256,
                verdict = Verdict.AMAN,
                score = 0,
                signals = listOf(
                    Signal(
                        code = "OFFICIAL_APP_VERIFIED",
                        weight = 0,
                        detail = "Verified official application"
                    )
                ),
                extractedUrls = inspection.extractedUrls,
                packageName = inspection.packageName,
                certSha256 = inspection.certSha256
            )
        }

        val signals = LinkedHashMap<String, Signal>()
        inspection.signals.forEach { signals.putIfAbsent(it.code, it) }

        if (inspection.fileType == FileType.APK) {
            if (hasSensitivePermission(inspection.permissions) && !signals.containsKey("APK_SENSITIVE_PERMISSIONS")) {
                signals["APK_SENSITIVE_PERMISSIONS"] = Signal(
                    code = "APK_SENSITIVE_PERMISSIONS",
                    weight = 35,
                    detail = "Requests sensitive permissions"
                )
            }

            val impersonatedEntry = findImpersonatedEntry(pkg, inspection.certSha256, officialEntry, allowlist)
            if (impersonatedEntry != null || reputation?.officialCertMatch == false) {
                val appLabel = impersonatedEntry?.appName ?: pkg ?: "official app"
                signals["APK_IMPERSONATION"] = Signal(
                    code = "APK_IMPERSONATION",
                    weight = 70,
                    detail = "Application impersonates $appLabel"
                )
            }

            if (fromChat) {
                signals.putIfAbsent(
                    "CHAT_SIDELOAD_APK",
                    Signal("CHAT_SIDELOAD_APK", 10, "APK received via chat")
                )
            }
        }

        if (isCloudMalicious) {
            signals["CLOUD_REPUTATION_MALICIOUS"] = Signal(
                code = "CLOUD_REPUTATION_MALICIOUS",
                weight = 80,
                detail = reputation?.threatCategory ?: "Flagged as malicious"
            )
        } else if (isCloudSuspicious) {
            signals["CLOUD_REPUTATION_SUSPICIOUS"] = Signal(
                code = "CLOUD_REPUTATION_SUSPICIOUS",
                weight = 40,
                detail = reputation?.threatCategory ?: "Flagged as suspicious"
            )
        }

        if (hasFlaggedUrls) {
            signals["CLOUD_FLAGGED_URL"] = Signal(
                code = "CLOUD_FLAGGED_URL",
                weight = 45,
                detail = "Contains flagged URLs"
            )
        }

        val effectiveSignals = signals.values.toList()
        val hasCorroboratingRisk = effectiveSignals.any { it.code !in NON_CORROBORATING_CODES }

        val rawScore = effectiveSignals
            .sumOf { effectiveWeight(it, hasCorroboratingRisk) }
            .coerceIn(0, 100)

        val hasCriticalSignal = effectiveSignals.any { it.code in CRITICAL_DANGEROUS_CODES }
        val isParseFailed = inspection.parseFailed || effectiveSignals.any { it.code == "PARSE_FAILED" }

        val finalVerdict: Verdict
        val finalScore: Int
        when {
            hasCriticalSignal || rawScore >= THRESHOLD_BERBAHAYA -> {
                finalVerdict = Verdict.BERBAHAYA
                finalScore = maxOf(rawScore, THRESHOLD_BERBAHAYA)
            }
            isParseFailed -> {
                finalVerdict = Verdict.MENCURIGAKAN
                finalScore = maxOf(rawScore, 40)
            }
            rawScore >= THRESHOLD_MENCURIGAKAN -> {
                finalVerdict = Verdict.MENCURIGAKAN
                finalScore = rawScore
            }
            else -> {
                finalVerdict = Verdict.AMAN
                finalScore = rawScore
            }
        }

        return AnalysisReport(
            fileName = inspection.fileName,
            fileType = inspection.fileType,
            sha256 = inspection.sha256,
            verdict = finalVerdict,
            score = finalScore,
            signals = effectiveSignals,
            extractedUrls = inspection.extractedUrls,
            packageName = inspection.packageName,
            certSha256 = inspection.certSha256
        )
    }

    private fun hasSensitivePermission(permissions: List<String>): Boolean {
        return permissions.any { perm ->
            val shortName = perm.substringAfterLast('.')
            shortName in SENSITIVE_PERMISSION_NAMES
        }
    }

    private fun findImpersonatedEntry(
        pkg: String?,
        certSha256: String?,
        exactEntry: OfficialAppEntry?,
        allowlist: Map<String, OfficialAppEntry>
    ): OfficialAppEntry? {
        if (exactEntry != null) {
            val matches = certSha256 != null && certSha256.equals(exactEntry.certSha256, ignoreCase = true)
            return if (matches) null else exactEntry
        }
        if (pkg.isNullOrBlank()) return null
        return allowlist.values.firstOrNull { entry ->
            pkg.startsWith("${entry.packageName}.") &&
                (certSha256 == null || !certSha256.equals(entry.certSha256, ignoreCase = true))
        }
    }

    private fun effectiveWeight(signal: Signal, hasCorroboratingRisk: Boolean): Int {
        return when (signal.code) {
            "APK_SENSITIVE_PERMISSIONS" -> if (hasCorroboratingRisk) maxOf(signal.weight, 35) else 15
            in CRITICAL_DANGEROUS_CODES -> maxOf(signal.weight, 70)
            "PARSE_FAILED" -> maxOf(signal.weight, 40)
            else -> signal.weight
        }
    }
}
