package id.chatguard.data

import android.content.ContentUris
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import id.chatguard.core.model.Verdict
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Locale
import java.util.UUID

data class ThreatActivityEntry(
    val id: String,
    val timestampMs: Long,
    val sourceLabel: String,
    val fileName: String,
    val verdict: Verdict,
    val whatFound: String,
    val impact: String,
    val advice: String,
    val lessonTip: String,
    val actionTaken: String
)

data class ThreatLearningStats(
    val totalDetected: Int,
    val totalBlocked: Int,
    val totalDeleted: Int,
    val learnedPatternsCount: Int
)

object ThreatActivityStore {

    private const val PREFS_NAME = "chatguard_threat_activity"
    private const val KEY_LOGS = "activity_logs_json"
    private const val KEY_BLOCKED_FILES = "blocked_files_set"
    private const val KEY_PATTERN_COUNTS = "learned_pattern_counts_json"
    private const val MAX_LOGS = 80
    private const val DEDUP_WINDOW_MS = 20_000L

    private fun prefs(context: Context): SharedPreferences {
        return context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    @Synchronized
    fun isBlocked(context: Context, fileName: String): Boolean {
        val normalized = normalizeFileName(fileName)
        if (normalized.isEmpty()) return false
        val set = prefs(context).getStringSet(KEY_BLOCKED_FILES, emptySet()).orEmpty()
        return normalized in set
    }

    @Synchronized
    fun getBlockedFiles(context: Context): Set<String> {
        return prefs(context).getStringSet(KEY_BLOCKED_FILES, emptySet()).orEmpty().toSet()
    }

    @Synchronized
    fun blockFile(context: Context, fileName: String) {
        val normalized = normalizeFileName(fileName)
        if (normalized.isEmpty()) return
        val p = prefs(context)
        val updated = p.getStringSet(KEY_BLOCKED_FILES, emptySet()).orEmpty().toMutableSet()
        updated.add(normalized)
        p.edit().putStringSet(KEY_BLOCKED_FILES, updated).apply()
    }

    @Synchronized
    fun unblockFile(context: Context, fileName: String) {
        val normalized = normalizeFileName(fileName)
        if (normalized.isEmpty()) return
        val p = prefs(context)
        val updated = p.getStringSet(KEY_BLOCKED_FILES, emptySet()).orEmpty().toMutableSet()
        if (updated.remove(normalized)) {
            p.edit().putStringSet(KEY_BLOCKED_FILES, updated).apply()
        }
    }

    @Synchronized
    fun recordAlert(
        context: Context,
        sourcePackage: String,
        fileName: String,
        verdict: Verdict,
        whatFound: String,
        impact: String,
        advice: String,
        lessonTip: String,
        reasons: List<String>,
        actionTaken: String,
        nowMs: Long = System.currentTimeMillis()
    ) {
        val p = prefs(context)
        val current = readLogsInternal(p).toMutableList()
        val sourceLabel = formatSourceLabel(sourcePackage)
        val normalized = normalizeFileName(fileName)

        val recentSame = current.firstOrNull {
            normalizeFileName(it.fileName) == normalized &&
                it.sourceLabel == sourceLabel &&
                (nowMs - it.timestampMs) < DEDUP_WINDOW_MS
        }
        if (recentSame != null) {
            return
        }

        val entry = ThreatActivityEntry(
            id = UUID.randomUUID().toString(),
            timestampMs = nowMs,
            sourceLabel = sourceLabel,
            fileName = fileName,
            verdict = verdict,
            whatFound = whatFound,
            impact = impact,
            advice = advice,
            lessonTip = lessonTip,
            actionTaken = actionTaken
        )
        current.add(0, entry)
        if (current.size > MAX_LOGS) {
            current.subList(MAX_LOGS, current.size).clear()
        }
        writeLogsInternal(p, current)
        incrementPatternsInternal(p, reasons)
    }

    @Synchronized
    fun updateLatestAction(
        context: Context,
        fileName: String,
        newAction: String
    ) {
        val p = prefs(context)
        val current = readLogsInternal(p).toMutableList()
        val normalized = normalizeFileName(fileName)
        val idx = current.indexOfFirst { normalizeFileName(it.fileName) == normalized }
        if (idx >= 0) {
            current[idx] = current[idx].copy(actionTaken = newAction)
            writeLogsInternal(p, current)
        }
    }

    @Synchronized
    fun getLogs(context: Context): List<ThreatActivityEntry> {
        return readLogsInternal(prefs(context))
    }

    @Synchronized
    fun clearLogs(context: Context) {
        prefs(context).edit()
            .remove(KEY_LOGS)
            .remove(KEY_PATTERN_COUNTS)
            .apply()
    }

    @Synchronized
    fun getStats(context: Context): ThreatLearningStats {
        val p = prefs(context)
        val logs = readLogsInternal(p)
        val blockedCount = getBlockedFiles(context).size
        val deletedCount = logs.count { it.actionTaken.contains("Hapus", ignoreCase = true) || it.actionTaken.contains("Delete", ignoreCase = true) }
        val patternJson = p.getString(KEY_PATTERN_COUNTS, null)
        val patternsCount = if (patternJson.isNullOrBlank()) 0 else {
            try {
                JSONObject(patternJson).length()
            } catch (_: Exception) {
                0
            }
        }
        return ThreatLearningStats(
            totalDetected = logs.size,
            totalBlocked = blockedCount,
            totalDeleted = deletedCount,
            learnedPatternsCount = patternsCount
        )
    }

    fun tryDeleteDownloadedFile(context: Context, fileName: String): Boolean {
        val targetName = fileName.trim()
        if (targetName.isEmpty()) return false
        var deletedAny = false

        val candidateDirs = buildList {
            try {
                add(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS))
            } catch (_: Exception) {
            }
            try {
                val ext = Environment.getExternalStorageDirectory()
                add(File(ext, "WhatsApp/Media/WhatsApp Documents"))
                add(File(ext, "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents"))
                add(File(ext, "Telegram/Telegram Documents"))
            } catch (_: Exception) {
            }
        }

        for (dir in candidateDirs) {
            try {
                if (!dir.exists() || !dir.isDirectory) continue
                val exact = File(dir, targetName)
                if (exact.exists() && exact.isFile && exact.delete()) {
                    deletedAny = true
                }
            } catch (_: Exception) {
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                val resolver = context.contentResolver
                val projection = arrayOf(MediaStore.Downloads._ID, MediaStore.Downloads.DISPLAY_NAME)
                val selection = "${MediaStore.Downloads.DISPLAY_NAME} = ?"
                resolver.query(
                    MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                    projection,
                    selection,
                    arrayOf(targetName),
                    null
                )?.use { cursor ->
                    val idCol = cursor.getColumnIndexOrThrow(MediaStore.Downloads._ID)
                    while (cursor.moveToNext()) {
                        val id = cursor.getLong(idCol)
                        val itemUri = ContentUris.withAppendedId(MediaStore.Downloads.EXTERNAL_CONTENT_URI, id)
                        if (resolver.delete(itemUri, null, null) > 0) {
                            deletedAny = true
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }

        return deletedAny
    }

    fun formatSourceLabel(sourcePackage: String): String {
        return when (sourcePackage.lowercase(Locale.ROOT)) {
            "com.whatsapp" -> "WhatsApp"
            "com.whatsapp.w4b" -> "WhatsApp Business"
            "org.telegram.messenger" -> "Telegram"
            "local_file" -> "Pemindaian File"
            else -> sourcePackage.ifBlank { "Chat" }
        }
    }

    private fun normalizeFileName(fileName: String): String {
        return fileName.trim().lowercase(Locale.ROOT)
    }

    private fun readLogsInternal(p: SharedPreferences): List<ThreatActivityEntry> {
        val raw = p.getString(KEY_LOGS, null) ?: return emptyList()
        return try {
            val arr = JSONArray(raw)
            val result = ArrayList<ThreatActivityEntry>(arr.length())
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                val verdictStr = obj.optString("verdict", Verdict.MENCURIGAKAN.name)
                val verdict = try {
                    Verdict.valueOf(verdictStr)
                } catch (_: Exception) {
                    Verdict.MENCURIGAKAN
                }
                result += ThreatActivityEntry(
                    id = obj.optString("id", UUID.randomUUID().toString()),
                    timestampMs = obj.optLong("timestampMs", 0L),
                    sourceLabel = obj.optString("sourceLabel", "Chat"),
                    fileName = obj.optString("fileName", ""),
                    verdict = verdict,
                    whatFound = obj.optString("whatFound", ""),
                    impact = obj.optString("impact", ""),
                    advice = obj.optString("advice", ""),
                    lessonTip = obj.optString("lessonTip", ""),
                    actionTaken = obj.optString("actionTaken", "Diperingatkan")
                )
            }
            result
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun writeLogsInternal(p: SharedPreferences, logs: List<ThreatActivityEntry>) {
        val arr = JSONArray()
        for (entry in logs) {
            val obj = JSONObject().apply {
                put("id", entry.id)
                put("timestampMs", entry.timestampMs)
                put("sourceLabel", entry.sourceLabel)
                put("fileName", entry.fileName)
                put("verdict", entry.verdict.name)
                put("whatFound", entry.whatFound)
                put("impact", entry.impact)
                put("advice", entry.advice)
                put("lessonTip", entry.lessonTip)
                put("actionTaken", entry.actionTaken)
            }
            arr.put(obj)
        }
        p.edit().putString(KEY_LOGS, arr.toString()).apply()
    }

    private fun incrementPatternsInternal(p: SharedPreferences, reasons: List<String>) {
        if (reasons.isEmpty()) return
        val raw = p.getString(KEY_PATTERN_COUNTS, null)
        val obj = try {
            if (raw.isNullOrBlank()) JSONObject() else JSONObject(raw)
        } catch (_: Exception) {
            JSONObject()
        }
        for (reason in reasons.distinct()) {
            val key = reason.trim()
            if (key.isEmpty()) continue
            obj.put(key, obj.optInt(key, 0) + 1)
        }
        p.edit().putString(KEY_PATTERN_COUNTS, obj.toString()).apply()
    }
}
