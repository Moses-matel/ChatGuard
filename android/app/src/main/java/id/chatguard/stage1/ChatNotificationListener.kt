package id.chatguard.stage1

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import id.chatguard.core.model.NotificationAlert
import id.chatguard.core.model.Verdict
import id.chatguard.ui.OverlayPopupManager
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
