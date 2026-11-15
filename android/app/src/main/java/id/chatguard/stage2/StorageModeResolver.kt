package id.chatguard.stage2

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay
import java.util.Locale

enum class StorageMode {
    ALL_FILES_WATCHER,
    PLAY_SAFE_MEDIASTORE_SAF
}

object StorageModeResolver {
    fun resolve(hasAllFilesAccess: Boolean): StorageMode {
        return if (hasAllFilesAccess) {
            StorageMode.ALL_FILES_WATCHER
        } else {
            StorageMode.PLAY_SAFE_MEDIASTORE_SAF
        }
    }

    fun hasAllFilesAccess(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.READ_EXTERNAL_STORAGE
            ) == PackageManager.PERMISSION_GRANTED
        }
    }

    fun resolveForContext(context: Context): StorageMode {
        return resolve(hasAllFilesAccess(context))
    }
}

object DownloadEventFilter {
    private val TEMP_SUFFIXES = setOf(
        ".tmp",
        ".part",
        ".crdownload",
        ".download",
        ".partial"
    )

    fun isTemporaryOrIgnoredFile(fileName: String): Boolean {
        val trimmed = fileName.trim()
        if (trimmed.isEmpty()) return true
        if (trimmed.startsWith(".")) return true
        val lower = trimmed.lowercase(Locale.ROOT)
        return TEMP_SUFFIXES.any { lower.endsWith(it) }
    }
}

class FileEventDebouncer(
    private val debounceWindowMs: Long = 2_000L,
    private val nowMs: () -> Long = { System.currentTimeMillis() }
) {
    private val lastSeen = LinkedHashMap<String, Long>()

    @Synchronized
    fun shouldProcess(key: String): Boolean {
        val now = nowMs()
        val prev = lastSeen[key]
        if (prev != null && (now - prev) < debounceWindowMs) {
            return false
        }
        lastSeen[key] = now
        if (lastSeen.size > MAX_TRACKED_KEYS) {
            val cutoff = now - debounceWindowMs
            val iter = lastSeen.entries.iterator()
            while (iter.hasNext()) {
                if (iter.next().value < cutoff) {
                    iter.remove()
                }
            }
        }
        return true
    }

    companion object {
        private const val MAX_TRACKED_KEYS = 500
    }
}

object FileStabilityChecker {
    suspend fun waitForStableSize(
        maxAttempts: Int = 10,
        checkIntervalMs: Long = 300L,
        sizeProvider: () -> Long,
        delayFn: suspend (Long) -> Unit = { delay(it) }
    ): Boolean {
        var previousSize = -1L
        for (attempt in 0 until maxAttempts) {
            val currentSize = sizeProvider()
            if (currentSize > 0L && currentSize == previousSize) {
                return true
            }
            previousSize = currentSize
            if (attempt < maxAttempts - 1) {
                delayFn(checkIntervalMs)
            }
        }
        return false
    }
}
