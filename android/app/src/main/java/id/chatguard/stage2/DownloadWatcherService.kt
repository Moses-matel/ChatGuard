package id.chatguard.stage2

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.provider.DocumentsContract
import android.provider.MediaStore
import android.provider.OpenableColumns
import androidx.core.app.NotificationCompat
import id.chatguard.analyzer.FileAnalyzerDispatcher
import id.chatguard.core.model.OfficialAppEntry
import id.chatguard.core.model.OfficialCertAllowlist
import id.chatguard.core.model.Verdict
import id.chatguard.data.ChatGuardDatabase
import id.chatguard.network.ReputationClient
import id.chatguard.scoring.PlainLanguageExplainer
import id.chatguard.scoring.RiskScorer
import id.chatguard.ui.OverlayPopupManager
import id.chatguard.ui.SettingsPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileOutputStream
import java.util.UUID

class DownloadWatcherService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val debouncer = FileEventDebouncer()
    private val safSeenTracker = SafSeenTracker()
    private val fileObservers = mutableListOf<FileObserver>()
    private var mediaStoreObserver: ContentObserver? = null

    @Volatile
    private var activeMode: StorageMode? = null

    @Volatile
    private var allowlist: Map<String, OfficialAppEntry> = emptyMap()

    private val settingsPreferences: SettingsPreferences by lazy {
        SettingsPreferences(applicationContext)
    }

    private val overlayPopupManager: OverlayPopupManager by lazy {
        OverlayPopupManager(applicationContext)
    }

    private val reputationClient: ReputationClient by lazy {
        val dao = ChatGuardDatabase.getInstance(applicationContext).reputationCacheDao()
        ReputationClient(
            baseUrlProvider = { settingsPreferences.getServerUrl() },
            cacheDao = dao
        )
    }

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannels()
        serviceScope.launch {
            allowlist = OfficialCertAllowlist.load(applicationContext)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startAsForeground()
        val mode = StorageModeResolver.resolveForContext(this)
        if (mode != activeMode) {
            stopWatchers()
            activeMode = mode
            when (mode) {
                StorageMode.ALL_FILES_WATCHER -> startAllFilesWatchers()
                StorageMode.PLAY_SAFE_MEDIASTORE_SAF -> startPlaySafeWatchers()
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopWatchers()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startAsForeground() {
        val notification = NotificationCompat.Builder(this, CHANNEL_WATCHER)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("ChatGuard Protection Active")
            .setContentText("Monitoring downloaded files for threats")
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID_FOREGROUND,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(NOTIFICATION_ID_FOREGROUND, notification)
        }
    }

    private fun startAllFilesWatchers() {
        val root = Environment.getExternalStorageDirectory() ?: return
        val candidateDirs = listOf(
            File(root, "Download"),
            File(root, "WhatsApp/Media/WhatsApp Documents"),
            File(root, "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents"),
            File(root, "Telegram/Telegram Documents"),
            File(root, "Android/media/org.telegram.messenger/Telegram/Telegram Documents")
        )

        for (dir in candidateDirs) {
            if (!dir.exists() || !dir.isDirectory || !dir.canRead()) continue
            val observer = createDirectoryObserver(dir)
            try {
                observer.startWatching()
                fileObservers.add(observer)
            } catch (_: Exception) {
            }
        }
    }

    @Suppress("DEPRECATION")
    private fun createDirectoryObserver(dir: File): FileObserver {
        val mask = FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            object : FileObserver(dir, mask) {
                override fun onEvent(event: Int, path: String?) {
                    handleObservedFile(dir, path)
                }
            }
        } else {
            object : FileObserver(dir.absolutePath, mask) {
                override fun onEvent(event: Int, path: String?) {
                    handleObservedFile(dir, path)
                }
            }
        }
    }

    private fun handleObservedFile(dir: File, relativePath: String?) {
        val name = relativePath ?: return
        if (DownloadEventFilter.isTemporaryOrIgnoredFile(name)) return
        val target = File(dir, name)
        val key = target.absolutePath
        if (!debouncer.shouldProcess(key)) return

        serviceScope.launch {
            val stable = FileStabilityChecker.waitForStableSize(
                sizeProvider = { if (target.exists() && target.isFile) target.length() else 0L }
            )
            if (!stable) return@launch
            inspectFileAndNotify(target, target.name, sourceUri = Uri.fromFile(target))
        }
    }

    private fun startPlaySafeWatchers() {
        val observedUri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            MediaStore.Downloads.EXTERNAL_CONTENT_URI
        } else {
            MediaStore.Files.getContentUri("external")
        }

        val observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean, uri: Uri?) {
                super.onChange(selfChange, uri)
                serviceScope.launch {
                    handleMediaStoreChange(uri ?: observedUri)
                    scanPersistedSafTrees()
                }
            }
        }

        try {
            contentResolver.registerContentObserver(observedUri, true, observer)
            mediaStoreObserver = observer
        } catch (_: Exception) {
        }

        serviceScope.launch {
            scanPersistedSafTrees()
        }
    }

    private suspend fun handleMediaStoreChange(uri: Uri) {
        val projection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            arrayOf(
                MediaStore.MediaColumns._ID,
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.SIZE,
                MediaStore.MediaColumns.IS_PENDING
            )
        } else {
            arrayOf(
                MediaStore.MediaColumns._ID,
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.SIZE
            )
        }
        val sortOrder = "${MediaStore.MediaColumns.DATE_MODIFIED} DESC"
        try {
            var itemUri: Uri? = null
            var displayName = ""
            contentResolver.query(uri, projection, null, null, sortOrder)?.use { cursor ->
                if (!cursor.moveToFirst()) return
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val pendingIdx = cursor.getColumnIndex(MediaStore.MediaColumns.IS_PENDING)
                    if (pendingIdx >= 0 && cursor.getInt(pendingIdx) == 1) {
                        return
                    }
                }
                val idIndex = cursor.getColumnIndex(MediaStore.MediaColumns._ID)
                val nameIndex = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)
                val id = if (idIndex >= 0) cursor.getLong(idIndex) else -1L
                displayName = if (nameIndex >= 0) cursor.getString(nameIndex).orEmpty() else ""

                if (DownloadEventFilter.isTemporaryOrIgnoredFile(displayName)) return

                val downloadsUri = MediaStore.Downloads.EXTERNAL_CONTENT_URI
                val filesUri = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                    MediaStore.Files.getContentUri("external")
                } else {
                    null
                }
                itemUri = if (shouldAppendMediaId(id, uri, downloadsUri, filesUri)) {
                    Uri.withAppendedPath(uri, id.toString())
                } else {
                    uri
                }
            }

            val resolvedUri = itemUri ?: return
            if (!debouncer.shouldProcess(resolvedUri.toString())) return

            val stable = FileStabilityChecker.waitForStableSize(
                sizeProvider = { queryContentSize(resolvedUri) }
            )
            if (!stable) return

            inspectContentUri(resolvedUri, displayName.ifBlank { "download_item" })
        } catch (_: Exception) {
        }
    }

    private fun queryContentSize(uri: Uri): Long {
        return try {
            contentResolver.query(uri, arrayOf(MediaStore.MediaColumns.SIZE), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val sizeIdx = cursor.getColumnIndex(MediaStore.MediaColumns.SIZE)
                    if (sizeIdx >= 0) cursor.getLong(sizeIdx) else 0L
                } else {
                    0L
                }
            } ?: 0L
        } catch (_: Exception) {
            0L
        }
    }

    private suspend fun scanPersistedSafTrees() {
        val persisted = try {
            contentResolver.persistedUriPermissions
        } catch (_: Exception) {
            emptyList()
        }
        for (perm in persisted) {
            if (!perm.isReadPermission) continue
            val treeUri = perm.uri
            try {
                val docId = DocumentsContract.getTreeDocumentId(treeUri)
                val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, docId)
                val projection = arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                    DocumentsContract.Document.COLUMN_LAST_MODIFIED
                )
                contentResolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
                    val idIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                    val nameIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                    val mimeIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
                    val modIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
                    while (cursor.moveToNext()) {
                        val childId = if (idIdx >= 0) cursor.getString(idIdx) else continue
                        val name = if (nameIdx >= 0) cursor.getString(nameIdx).orEmpty() else continue
                        val mime = if (mimeIdx >= 0) cursor.getString(mimeIdx).orEmpty() else ""
                        if (mime == DocumentsContract.Document.MIME_TYPE_DIR) continue
                        if (DownloadEventFilter.isTemporaryOrIgnoredFile(name)) continue

                        val lastModified = if (modIdx >= 0 && !cursor.isNull(modIdx)) cursor.getLong(modIdx) else 0L
                        val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, childId)
                        if (!safSeenTracker.shouldInspect(docUri.toString(), lastModified)) continue
                        if (!debouncer.shouldProcess(docUri.toString())) continue
                        inspectContentUri(docUri, name)
                    }
                }
            } catch (_: Exception) {
            }
        }
    }

    private suspend fun inspectContentUri(uri: Uri, fallbackName: String) {
        val displayName = resolveDisplayName(contentResolver, uri) ?: fallbackName
        if (DownloadEventFilter.isTemporaryOrIgnoredFile(displayName)) return

        val tempFile = createTempCopyFile(cacheDir, displayName)
        try {
            val copied = copyUriToTempFile(contentResolver, uri, tempFile, MAX_INSPECT_BYTES)
            if (!copied) return
            inspectFileAndNotify(tempFile, displayName, sourceUri = uri)
        } finally {
            tempFile.delete()
        }
    }

    private suspend fun inspectFileAndNotify(
        file: File,
        displayName: String,
        sourceUri: Uri? = null
    ) {
        val currentAllowlist = allowlist.ifEmpty {
            OfficialCertAllowlist.load(applicationContext).also { allowlist = it }
        }
        val rawInspection = FileAnalyzerDispatcher.inspect(file)
        val inspection = if (rawInspection.fileName != displayName) {
            rawInspection.copy(fileName = displayName)
        } else {
            rawInspection
        }

        val reputation = reputationClient.check(
            sha256 = inspection.sha256,
            urls = inspection.extractedUrls,
            certSha256 = inspection.certSha256
        )

        val report = RiskScorer.evaluate(
            inspection = inspection,
            reputation = reputation,
            allowlist = currentAllowlist,
            fromChat = true
        )

        if (report.verdict != Verdict.AMAN) {
            val explained = PlainLanguageExplainer.explain(report, settingsPreferences.getLocale())
            overlayPopupManager.showStage2(
                explained = explained,
                report = report,
                fileUri = sourceUri,
                onDeleteFile = {
                    serviceScope.launch {
                        deleteObservedFile(sourceUri, file)
                    }
                },
                onSubmitReport = { feedback ->
                    serviceScope.launch {
                        reputationClient.submitReport(feedback)
                    }
                }
            )
        }
    }

    private fun deleteObservedFile(sourceUri: Uri?, fallbackFile: File) {
        try {
            SafeFileDeleter.delete(this, sourceUri)
            if (fallbackFile.exists()) {
                fallbackFile.delete()
            }
        } catch (_: Exception) {
        }
    }

    private fun stopWatchers() {
        for (observer in fileObservers) {
            try {
                observer.stopWatching()
            } catch (_: Exception) {
            }
        }
        fileObservers.clear()

        mediaStoreObserver?.let {
            try {
                contentResolver.unregisterContentObserver(it)
            } catch (_: Exception) {
            }
        }
        mediaStoreObserver = null
    }

    private fun ensureNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return

        val watcherChannel = NotificationChannel(
            CHANNEL_WATCHER,
            "Download Protection",
            NotificationManager.IMPORTANCE_LOW
        )
        val alertChannel = NotificationChannel(
            CHANNEL_ALERTS,
            "Threat Alerts",
            NotificationManager.IMPORTANCE_HIGH
        )
        manager.createNotificationChannel(watcherChannel)
        manager.createNotificationChannel(alertChannel)
    }

    companion object {
        const val CHANNEL_WATCHER = "chatguard_watcher"
        const val CHANNEL_ALERTS = "chatguard_alerts"
        const val NOTIFICATION_ID_FOREGROUND = 2001
        const val MAX_INSPECT_BYTES = 100L * 1024L * 1024L // 100 MB

        internal fun shouldAppendMediaId(
            id: Long,
            uri: Uri,
            downloadsUri: Uri,
            filesUri: Uri?,
            sdkInt: Int = Build.VERSION.SDK_INT
        ): Boolean {
            if (id < 0) return false
            return uri == downloadsUri ||
                (sdkInt < Build.VERSION_CODES.Q && filesUri != null && uri == filesUri)
        }

        internal fun resolveDisplayName(resolver: ContentResolver, uri: Uri): String? {
            if (uri.scheme == ContentResolver.SCHEME_FILE) {
                return uri.lastPathSegment
            }
            return try {
                resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (idx >= 0) cursor.getString(idx) else null
                    } else {
                        null
                    }
                }
            } catch (_: Exception) {
                null
            } ?: uri.lastPathSegment
        }

        internal fun createTempCopyFile(cacheDir: File, displayName: String): File {
            val sanitized = displayName.replace(Regex("""[^A-Za-z0-9._-]"""), "_").take(64)
                .ifBlank { "inspect_target" }
            return File(cacheDir, "safe_inspect_${UUID.randomUUID()}_$sanitized")
        }

        internal fun copyUriToTempFile(
            resolver: ContentResolver,
            uri: Uri,
            destFile: File,
            maxBytes: Long = MAX_INSPECT_BYTES
        ): Boolean {
            return try {
                val inputStream = if (uri.scheme == ContentResolver.SCHEME_FILE) {
                    val path = uri.path ?: return false
                    File(path).inputStream()
                } else {
                    resolver.openInputStream(uri) ?: return false
                }
                inputStream.use { input ->
                    FileOutputStream(destFile).use { output ->
                        val buffer = ByteArray(8192)
                        var total = 0L
                        while (true) {
                            val read = input.read(buffer)
                            if (read <= 0) break
                            total += read
                            if (total > maxBytes) {
                                return false
                            }
                            output.write(buffer, 0, read)
                        }
                    }
                }
                true
            } catch (_: Exception) {
                false
            }
        }
    }
}
