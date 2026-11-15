package id.chatguard.stage2

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class StorageModeResolverTest {

    @Test
    fun `resolve returns ALL_FILES_WATCHER when all-files access is granted`() {
        assertEquals(StorageMode.ALL_FILES_WATCHER, StorageModeResolver.resolve(hasAllFilesAccess = true))
    }

    @Test
    fun `resolve returns PLAY_SAFE_MEDIASTORE_SAF when all-files access is denied`() {
        assertEquals(StorageMode.PLAY_SAFE_MEDIASTORE_SAF, StorageModeResolver.resolve(hasAllFilesAccess = false))
    }

    @Test
    fun `isTemporaryOrIgnoredFile filters tmp, part, crdownload, and pending files`() {
        assertTrue(DownloadEventFilter.isTemporaryOrIgnoredFile("invoice.pdf.tmp"))
        assertTrue(DownloadEventFilter.isTemporaryOrIgnoredFile("app.apk.PART"))
        assertTrue(DownloadEventFilter.isTemporaryOrIgnoredFile("archive.zip.crdownload"))
        assertTrue(DownloadEventFilter.isTemporaryOrIgnoredFile("doc.docx.download"))
        assertTrue(DownloadEventFilter.isTemporaryOrIgnoredFile("file.partial"))
        assertTrue(DownloadEventFilter.isTemporaryOrIgnoredFile(".pending-1700000-invoice.pdf"))
        assertTrue(DownloadEventFilter.isTemporaryOrIgnoredFile(".trashed-123-file.apk"))
        assertTrue(DownloadEventFilter.isTemporaryOrIgnoredFile("   "))

        assertFalse(DownloadEventFilter.isTemporaryOrIgnoredFile("undangan_nikah.apk"))
        assertFalse(DownloadEventFilter.isTemporaryOrIgnoredFile("resi_paket.pdf"))
        assertFalse(DownloadEventFilter.isTemporaryOrIgnoredFile("tagihan.docx"))
        assertFalse(DownloadEventFilter.isTemporaryOrIgnoredFile("laporan.xlsx"))
        assertFalse(DownloadEventFilter.isTemporaryOrIgnoredFile("dokumen.zip"))
        assertFalse(DownloadEventFilter.isTemporaryOrIgnoredFile("arsip.rar"))
    }

    @Test
    fun `debouncer suppresses duplicate events within window and allows after window`() {
        var now = 1_000L
        val debouncer = FileEventDebouncer(debounceWindowMs = 2_000L, nowMs = { now })

        assertTrue(debouncer.shouldProcess("/storage/emulated/0/Download/undangan.apk"))
        // Immediate duplicate
        now = 1_500L
        assertFalse(debouncer.shouldProcess("/storage/emulated/0/Download/undangan.apk"))
        // Different file in same window is allowed
        assertTrue(debouncer.shouldProcess("/storage/emulated/0/Download/invoice.pdf"))
        // Still inside 2000ms window for first file
        now = 2_999L
        assertFalse(debouncer.shouldProcess("/storage/emulated/0/Download/undangan.apk"))
        // Past 2000ms window
        now = 3_000L
        assertTrue(debouncer.shouldProcess("/storage/emulated/0/Download/undangan.apk"))
    }

    @Test
    fun `waitForStableSize returns true once size is positive and stops changing`() = runTest {
        val sizes = ArrayDeque(listOf(1024L, 2048L, 2048L))
        val stable = FileStabilityChecker.waitForStableSize(
            maxAttempts = 5,
            checkIntervalMs = 1L,
            sizeProvider = { sizes.removeFirstOrNull() ?: 2048L },
            delayFn = {}
        )
        assertTrue(stable)
    }

    @Test
    fun `waitForStableSize returns false when file never stabilizes or stays zero`() = runTest {
        var growing = 0L
        val unstable = FileStabilityChecker.waitForStableSize(
            maxAttempts = 4,
            checkIntervalMs = 1L,
            sizeProvider = {
                growing += 512L
                growing
            },
            delayFn = {}
        )
        assertFalse(unstable)

        val empty = FileStabilityChecker.waitForStableSize(
            maxAttempts = 3,
            checkIntervalMs = 1L,
            sizeProvider = { 0L },
            delayFn = {}
        )
        assertFalse(empty)
    }

    @Test
    fun `safSeenTracker skips already-scanned documents with same lastModified and reinspects when modified`() {
        val tracker = SafSeenTracker(maxEntries = 2)

        assertTrue(tracker.shouldInspect("content://tree/doc1", 1000L))
        // Same docUri and same lastModified -> skip
        assertFalse(tracker.shouldInspect("content://tree/doc1", 1000L))
        // Same docUri with newer lastModified -> inspect
        assertTrue(tracker.shouldInspect("content://tree/doc1", 2000L))
        assertFalse(tracker.shouldInspect("content://tree/doc1", 2000L))

        // Fill capacity and evict oldest (doc1)
        assertTrue(tracker.shouldInspect("content://tree/doc2", 1000L))
        assertTrue(tracker.shouldInspect("content://tree/doc3", 1000L))

        // doc1 was evicted when doc3 was inserted, so it should be inspectable again
        assertTrue(tracker.shouldInspect("content://tree/doc1", 2000L))
    }

    @Test
    fun `safeFileDeleter deletes file scheme uri and handles null or missing files`() {
        val context = mockk<Context>(relaxed = true)
        val tempFile = File.createTempFile("chatguard_delete_test", ".apk")
        assertTrue(tempFile.exists())

        val fileUri = mockk<Uri> {
            every { scheme } returns ContentResolver.SCHEME_FILE
            every { path } returns tempFile.absolutePath
        }

        assertTrue(SafeFileDeleter.delete(context, fileUri))
        assertFalse(tempFile.exists())
        assertFalse(SafeFileDeleter.delete(context, fileUri))
        assertFalse(SafeFileDeleter.delete(context, null))
    }
}
