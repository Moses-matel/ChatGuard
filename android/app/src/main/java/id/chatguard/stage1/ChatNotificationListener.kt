package id.chatguard.stage1

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import id.chatguard.core.model.NotificationAlert
import id.chatguard.core.model.Verdict
import id.chatguard.data.ThreatActivityStore
import id.chatguard.scoring.Stage1Explainer
import id.chatguard.ui.OverlayPopupManager
import id.chatguard.ui.SettingsPreferences
import java.util.concurrent.CopyOnWriteArrayList

/**
 * NotificationListenerService that inspects incoming chat notifications for phishing files.
 *
 * Privacy guarantee: Never persists or logs raw message contents to disk or network.
 */
class ChatNotificationListener : NotificationListenerService() {

    private val overlayPopupManager: OverlayPopupManager? by lazy {
        try {
            applicationContext?.let { OverlayPopupManager(it) }
        } catch (_: Exception) {
            null
        }
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return
        try {
            if (applicationContext != null && !SettingsPreferences(applicationContext).isSafeModeEnabled()) {
                return
            }
        } catch (_: Exception) {
        }

        val packageName = sbn.packageName ?: return
        if (packageName.lowercase() !in NotificationAnalyzer.SUPPORTED_PACKAGES) {
            return
        }

        val notification = sbn.notification ?: return
        val extras = notification.extras ?: return

        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString().orEmpty()
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString().orEmpty()

        processNotification(packageName, title, text, bigText)
    }

    internal fun processNotification(
        packageName: String,
        title: String,
        text: String,
        bigText: String = ""
    ): NotificationAlert? {
        val messageContent = if (bigText.isNotBlank() && bigText != text) {
            "$text\n$bigText"
        } else {
            text
        }

        val alert = NotificationAnalyzer.analyze(
            packageName = packageName,
            title = title,
            text = messageContent
        ) ?: return null

        dispatchAlert(alert)
        return alert
    }

    internal fun dispatchAlert(alert: NotificationAlert) {
        if (alert.verdict != Verdict.AMAN) {
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
            notifyAlert(alert)
            overlayPopupManager?.showStage1(alert)
        }
    }

    private fun notifyAlert(alert: NotificationAlert) {
        for (listener in alertListeners) {
            try {
                listener(alert)
            } catch (_: Exception) {
            }
        }
    }

    companion object {
        private val alertListeners = CopyOnWriteArrayList<(NotificationAlert) -> Unit>()

        fun addListener(listener: (NotificationAlert) -> Unit) {
            alertListeners.add(listener)
        }

        fun removeListener(listener: (NotificationAlert) -> Unit) {
            alertListeners.remove(listener)
        }

        fun clearListeners() {
            alertListeners.clear()
        }
    }
}
