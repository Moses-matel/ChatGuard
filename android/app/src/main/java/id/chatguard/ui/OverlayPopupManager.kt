package id.chatguard.ui

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.app.NotificationCompat
import id.chatguard.core.model.AnalysisReport
import id.chatguard.core.model.NotificationAlert
import id.chatguard.core.model.Verdict
import id.chatguard.core.model.VerdictFeedbackRequest
import id.chatguard.scoring.ExplainedReport
import id.chatguard.stage2.DownloadWatcherService
import id.chatguard.stage2.SafeInspectActivity

class OverlayPopupManager(context: Context) {

    private val appContext = context.applicationContext
    private val mainHandler = Handler(Looper.getMainLooper())
    private val settingsPreferences = SettingsPreferences(appContext)
    private val windowManager: WindowManager? =
        appContext.getSystemService(Context.WINDOW_SERVICE) as? WindowManager

    private var currentOverlayView: View? = null

    fun showStage1(alert: NotificationAlert) {
        val isId = isIndonesian()
        if (!canShowOverlay()) {
            postStage1FallbackNotification(alert, isId)
            return
        }

        runOnMainThread {
            val shown = showOverlayView(buildStage1View(alert, isId), Gravity.TOP or Gravity.CENTER_HORIZONTAL)
            if (!shown) {
                postStage1FallbackNotification(alert, isId)
            }
        }
    }

    fun showStage2(
        explained: ExplainedReport,
        report: AnalysisReport,
        fileUri: Uri?,
        onDeleteFile: () -> Unit,
        onSubmitReport: (VerdictFeedbackRequest) -> Unit
    ) {
        val isId = isIndonesian()
        if (!canShowOverlay()) {
            postStage2FallbackNotification(explained, report, fileUri)
            return
        }

        runOnMainThread {
            val view = buildStage2View(
                explained = explained,
                report = report,
                isId = isId,
                onDeleteFile = onDeleteFile,
                onSubmitReport = onSubmitReport
            )
            val shown = showOverlayView(view, Gravity.CENTER)
            if (!shown) {
                postStage2FallbackNotification(explained, report, fileUri)
            }
        }
    }

    fun dismiss() {
        runOnMainThread {
            dismissImmediate()
        }
    }

    private fun canShowOverlay(): Boolean {
        return try {
            Settings.canDrawOverlays(appContext) && windowManager != null
        } catch (_: Exception) {
            false
        }
    }

    private fun runOnMainThread(block: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            block()
        } else {
            mainHandler.post(block)
        }
    }

    private fun showOverlayView(view: View, gravity: Int): Boolean {
        val wm = windowManager ?: return false
        dismissImmediate()

        val overlayType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            overlayType,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            this.gravity = gravity
            y = dp(24)
        }

        return try {
            wm.addView(view, params)
            currentOverlayView = view
            true
        } catch (_: Exception) {
            currentOverlayView = null
            false
        }
    }

    private fun dismissImmediate() {
        val existing = currentOverlayView ?: return
        currentOverlayView = null
        try {
            windowManager?.removeViewImmediate(existing)
        } catch (_: Exception) {
            try {
                windowManager?.removeView(existing)
            } catch (_: Exception) {
            }
        }
    }

    private fun buildStage1View(alert: NotificationAlert, isId: Boolean): View {
        val container = createCardContainer(borderColor = verdictColor(alert.verdict))

        val badge = createBadgeView(alert.verdict, isId)
        container.addView(badge)

        val title = TextView(appContext).apply {
            text = if (isId) {
                "Peringatan File Chat Mencurigakan"
            } else {
                "Suspicious Chat File Warning"
            }
            setTextColor(Color.parseColor("#111827"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(8), 0, dp(4))
        }
        container.addView(title)

        val senderLine = TextView(appContext).apply {
            text = if (isId) "Pengirim: ${alert.sender}" else "Sender: ${alert.sender}"
            setTextColor(Color.parseColor("#374151"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
        }
        container.addView(senderLine)

        val fileLine = TextView(appContext).apply {
            text = if (isId) "File: ${alert.fileName}" else "File: ${alert.fileName}"
            setTextColor(Color.parseColor("#1F2937"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(2), 0, dp(6))
        }
        container.addView(fileLine)

        val warningText = TextView(appContext).apply {
            val detail = alert.reasons.firstOrNull()?.takeIf { it.isNotBlank() }
            text = detail ?: if (isId) {
                "Jangan langsung memasang atau membuka file ini sebelum diperiksa oleh ChatGuard."
            } else {
                "Do not install or open this file until ChatGuard checks it."
            }
            setTextColor(Color.parseColor("#4B5563"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setPadding(0, 0, 0, dp(10))
        }
        container.addView(warningText)

        val closeBtn = Button(appContext).apply {
            text = if (isId) "Tutup" else "Close"
            setOnClickListener { dismiss() }
        }
        container.addView(closeBtn)

        return wrapWithOuterMargin(container)
    }

    private fun buildStage2View(
        explained: ExplainedReport,
        report: AnalysisReport,
        isId: Boolean,
        onDeleteFile: () -> Unit,
        onSubmitReport: (VerdictFeedbackRequest) -> Unit
    ): View {
        val scroll = ScrollView(appContext)
        val container = createCardContainer(borderColor = verdictColor(explained.verdict))

        container.addView(createBadgeView(explained.verdict, isId))

        val titleView = TextView(appContext).apply {
            text = explained.title
            setTextColor(Color.parseColor("#111827"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 17f)
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(8), 0, dp(4))
        }
        container.addView(titleView)

        val fileView = TextView(appContext).apply {
            text = if (isId) "File: ${report.fileName}" else "File: ${report.fileName}"
            setTextColor(Color.parseColor("#4B5563"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setPadding(0, 0, 0, dp(10))
        }
        container.addView(fileView)

        container.addView(createSectionHeader(if (isId) "Apa isi file ini?" else "What is inside this file?"))
        container.addView(createSectionBody(explained.whatInside))

        container.addView(createSectionHeader(if (isId) "Apa dampaknya jika dibuka?" else "What happens if opened?"))
        container.addView(createSectionBody(explained.impact))

        val consentPanel = LinearLayout(appContext).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            setPadding(dp(12), dp(10), dp(12), dp(10))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#F3F4F6"))
                cornerRadius = dp(8).toFloat()
            }
        }

        val consentPrompt = TextView(appContext).apply {
            text = if (isId) {
                "Persetujuan: Hanya metadata anonim (hash SHA-256, tipe file, nama paket, hash sertifikat, dan hasil penilaian) yang akan dikirim ke server. Isi file dan pesan chat Anda TIDAK pernah dikirim."
            } else {
                "Consent: Only anonymous metadata (SHA-256 hash, file type, package name, certificate hash, and verdict) will be sent to the server. Your file contents and chat messages are NEVER sent."
            }
            setTextColor(Color.parseColor("#1F2937"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(0, 0, 0, dp(8))
        }
        consentPanel.addView(consentPrompt)

        val consentActions = LinearLayout(appContext).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        val confirmSendBtn = Button(appContext).apply {
            text = if (isId) "Kirim Laporan" else "Send Report"
            setOnClickListener {
                val feedback = VerdictFeedbackRequest(
                    sha256 = report.sha256,
                    fileType = report.fileType.name,
                    packageName = report.packageName,
                    certSha256 = report.certSha256,
                    shownVerdict = report.verdict.name,
                    userNote = null
                )
                onSubmitReport(feedback)
                dismiss()
            }
        }
        val cancelConsentBtn = Button(appContext).apply {
            text = if (isId) "Batal" else "Cancel"
            setOnClickListener {
                consentPanel.visibility = View.GONE
            }
        }
        consentActions.addView(confirmSendBtn)
        consentActions.addView(cancelConsentBtn)
        consentPanel.addView(consentActions)

        val actionRow = LinearLayout(appContext).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(10), 0, dp(4))
        }

        val deleteBtn = Button(appContext).apply {
            text = if (isId) "Hapus File" else "Delete File"
            setTextColor(Color.WHITE)
            backgroundTintList = android.content.res.ColorStateList.valueOf(Color.parseColor("#C62828"))
            setOnClickListener {
                onDeleteFile()
                dismiss()
            }
        }
        val ignoreBtn = Button(appContext).apply {
            text = if (isId) "Abaikan (Risiko)" else "Ignore (Risk)"
            setOnClickListener { dismiss() }
        }
        actionRow.addView(deleteBtn)
        actionRow.addView(ignoreBtn)
        container.addView(actionRow)

        val reportBtn = Button(appContext).apply {
            text = if (isId) "Laporkan hasil keliru" else "Report incorrect result"
            setOnClickListener {
                consentPanel.visibility = View.VISIBLE
            }
        }
        container.addView(reportBtn)
        container.addView(consentPanel)

        scroll.addView(wrapWithOuterMargin(container))
        return scroll
    }

    private fun createCardContainer(borderColor: Int): LinearLayout {
        return LinearLayout(appContext).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(14))
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = dp(14).toFloat()
                setStroke(dp(2), borderColor)
            }
            elevation = dp(8).toFloat()
        }
    }

    private fun wrapWithOuterMargin(child: View): View {
        return LinearLayout(appContext).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(8), dp(16), dp(8))
            addView(child)
        }
    }

    private fun createBadgeView(verdict: Verdict, isId: Boolean): TextView {
        val label = when (verdict) {
            Verdict.AMAN -> if (isId) "Aman" else "Safe"
            Verdict.MENCURIGAKAN -> if (isId) "Mencurigakan" else "Suspicious"
            Verdict.BERBAHAYA -> if (isId) "Berbahaya" else "Dangerous"
        }
        return TextView(appContext).apply {
            text = label
            setTextColor(Color.WHITE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTypeface(typeface, Typeface.BOLD)
            setPadding(dp(10), dp(4), dp(10), dp(4))
            background = GradientDrawable().apply {
                setColor(verdictColor(verdict))
                cornerRadius = dp(8).toFloat()
            }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }
    }

    private fun createSectionHeader(textValue: String): TextView {
        return TextView(appContext).apply {
            text = textValue
            setTextColor(Color.parseColor("#111827"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(6), 0, dp(2))
        }
    }

    private fun createSectionBody(textValue: String): TextView {
        return TextView(appContext).apply {
            text = textValue
            setTextColor(Color.parseColor("#374151"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setPadding(0, 0, 0, dp(6))
        }
    }

    private fun verdictColor(verdict: Verdict): Int {
        return when (verdict) {
            Verdict.AMAN -> Color.parseColor("#2E7D32")
            Verdict.MENCURIGAKAN -> Color.parseColor("#ED6C02")
            Verdict.BERBAHAYA -> Color.parseColor("#C62828")
        }
    }

    private fun postStage1FallbackNotification(alert: NotificationAlert, isId: Boolean) {
        ensureAlertChannel()
        val title = if (isId) {
            "Peringatan File Chat: ${alert.fileName}"
        } else {
            "Chat File Warning: ${alert.fileName}"
        }
        val body = alert.reasons.firstOrNull()?.takeIf { it.isNotBlank() } ?: if (isId) {
            "Pengirim: ${alert.sender}. Hati-hati sebelum membuka file ini."
        } else {
            "Sender: ${alert.sender}. Be careful before opening this file."
        }

        val notification = NotificationCompat.Builder(appContext, DownloadWatcherService.CHANNEL_ALERTS)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        val manager = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        manager?.notify((alert.sender + alert.fileName).hashCode(), notification)
    }

    private fun postStage2FallbackNotification(
        explained: ExplainedReport,
        report: AnalysisReport,
        fileUri: Uri?
    ) {
        ensureAlertChannel()
        val inspectIntent = Intent(appContext, SafeInspectActivity::class.java).apply {
            action = Intent.ACTION_VIEW
            if (fileUri != null) {
                data = fileUri
                if (fileUri.scheme == ContentResolver.SCHEME_CONTENT) {
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
            }
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val pendingIntent = PendingIntent.getActivity(
            appContext,
            report.sha256.hashCode(),
            inspectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(appContext, DownloadWatcherService.CHANNEL_ALERTS)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(explained.title)
            .setContentText(explained.whatInside)
            .setStyle(NotificationCompat.BigTextStyle().bigText("${explained.whatInside}\n${explained.impact}"))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        val manager = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        manager?.notify(report.sha256.hashCode(), notification)
    }

    private fun ensureAlertChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        val existing = manager.getNotificationChannel(DownloadWatcherService.CHANNEL_ALERTS)
        if (existing == null) {
            val channel = NotificationChannel(
                DownloadWatcherService.CHANNEL_ALERTS,
                "Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            )
            manager.createNotificationChannel(channel)
        }
    }

    private fun isIndonesian(): Boolean {
        return settingsPreferences.getLanguage() != SettingsPreferences.LANG_ENGLISH
    }

    private fun dp(value: Int): Int {
        return TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            value.toFloat(),
            appContext.resources.displayMetrics
        ).toInt()
    }
}
