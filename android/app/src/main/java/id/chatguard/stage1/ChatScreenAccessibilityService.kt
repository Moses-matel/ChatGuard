package id.chatguard.stage1

import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import id.chatguard.core.model.NotificationAlert
import id.chatguard.core.model.Verdict
import id.chatguard.data.ThreatActivityStore
import id.chatguard.scoring.Stage1Explainer
import id.chatguard.ui.OverlayPopupManager
import id.chatguard.ui.SettingsPreferences
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap

/**
 * Pure in-memory scanner + cooldown deduplicator for visible chat screen texts.
 * Never persists or logs raw chat contents.
 */
internal class ChatScreenScanner(
    private val cooldownMs: Long = DEFAULT_COOLDOWN_MS
) {
    private val recentAlerts = ConcurrentHashMap<String, Long>()

    fun findAlerts(
        packageName: String,
        visibleTexts: List<String>,
        nowMs: Long = System.currentTimeMillis()
    ): List<NotificationAlert> {
        val pkg = packageName.lowercase()
        if (pkg !in NotificationAnalyzer.SUPPORTED_PACKAGES) {
            return emptyList()
        }

        pruneExpired(nowMs)

        val emitted = mutableListOf<NotificationAlert>()
        for (raw in visibleTexts) {
            if (raw.isBlank()) continue
            val alert = NotificationAnalyzer.analyze(
                packageName = pkg,
                title = "Layar Chat",
                text = raw
            ) ?: continue

            if (alert.verdict == Verdict.AMAN) continue

            val dedupKey = "$pkg|${alert.fileName.lowercase()}"
            val lastSeen = recentAlerts[dedupKey]
            if (lastSeen != null && (nowMs - lastSeen) < cooldownMs) {
                continue
            }

            recentAlerts[dedupKey] = nowMs
            emitted += alert
        }
        return emitted
    }

    private fun pruneExpired(nowMs: Long) {
        if (recentAlerts.size <= 100) return
        val iterator = recentAlerts.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if ((nowMs - entry.value) >= cooldownMs) {
                iterator.remove()
            }
        }
    }

    companion object {
        const val DEFAULT_COOLDOWN_MS = 600_000L
    }
}

/**
 * Optional AccessibilityService (for personal/sideload builds) that inspects visible
 * filenames inside WhatsApp/Telegram chats and shows the Stage 1 overlay popup
 * without requiring an incoming notification or file download.
 */
class ChatScreenAccessibilityService : AccessibilityService() {

    private val scanner = ChatScreenScanner()

    @Volatile
    private var lastScanAtMs: Long = 0L

    private val overlayPopupManager: OverlayPopupManager? by lazy {
        try {
            applicationContext?.let { OverlayPopupManager(it) }
        } catch (_: Exception) {
            null
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return
        try {
            if (applicationContext != null && !SettingsPreferences(applicationContext).isSafeModeEnabled()) {
                return
            }
        } catch (_: Exception) {
        }
        if (overlayPopupManager?.isShowing() == true) return
        val packageName = event.packageName?.toString()?.lowercase() ?: return
        if (packageName !in NotificationAnalyzer.SUPPORTED_PACKAGES) return

        val now = System.currentTimeMillis()
        if (now - lastScanAtMs < SCAN_THROTTLE_MS) return
        lastScanAtMs = now

        val root = try {
            rootInActiveWindow
        } catch (_: Exception) {
            null
        } ?: return

        val visibleTexts = collectVisibleTexts(root)
        val alerts = scanner.findAlerts(packageName, visibleTexts, now)
        for (alert in alerts) {
            try {
                applicationContext?.let { ctx ->
                    val isId = SettingsPreferences(ctx).getLanguage() != SettingsPreferences.LANG_ENGLISH
                    val blocked = ThreatActivityStore.isBlocked(ctx, alert.fileName)
                    val explanation = Stage1Explainer.explain(alert, isBlocked = blocked, isIndonesian = isId)
                    ThreatActivityStore.recordAlert(
                        context = ctx,
                        sourcePackage = alert.sourcePackage,
                        fileName = alert.fileName,
                        verdict = if (blocked) Verdict.BERBAHAYA else alert.verdict,
                        whatFound = explanation.whatFound,
                        impact = explanation.impact,
                        advice = explanation.advice,
                        lessonTip = explanation.lessonTip,
                        reasons = alert.reasons,
                        actionTaken = if (blocked) {
                            if (isId) "Diblokir" else "Blocked"
                        } else {
                            if (isId) "Diperingatkan" else "Warned"
                        }
                    )
                }
            } catch (_: Exception) {
            }
            overlayPopupManager?.showStage1(alert)
        }
    }

    override fun onInterrupt() {
        // Nothing to clean up; no state or message content is persisted.
    }

    private fun collectVisibleTexts(root: AccessibilityNodeInfo): List<String> {
        val texts = ArrayList<String>(32)
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        queue.add(root)
        var visited = 0

        while (queue.isNotEmpty() && visited < MAX_NODES) {
            val node = queue.removeFirst()
            visited++

            val nodeText = node.text?.toString()?.trim()
            if (!nodeText.isNullOrEmpty() && nodeText.length <= MAX_SNIPPET_LENGTH) {
                texts += nodeText
            }
            val desc = node.contentDescription?.toString()?.trim()
            if (!desc.isNullOrEmpty() && desc != nodeText && desc.length <= MAX_SNIPPET_LENGTH) {
                texts += desc
            }

            val childCount = node.childCount
            for (i in 0 until childCount) {
                val child = try {
                    node.getChild(i)
                } catch (_: Exception) {
                    null
                }
                if (child != null) {
                    queue.addLast(child)
                }
            }
        }
        return texts
    }

    companion object {
        private const val SCAN_THROTTLE_MS = 500L
        private const val MAX_NODES = 250
        private const val MAX_SNIPPET_LENGTH = 512
    }
}
