package id.chatguard.stage2

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.IntentCompat
import androidx.lifecycle.lifecycleScope
import id.chatguard.analyzer.FileAnalyzerDispatcher
import id.chatguard.core.model.AnalysisReport
import id.chatguard.core.model.OfficialCertAllowlist
import id.chatguard.core.model.Verdict
import id.chatguard.data.ChatGuardDatabase
import id.chatguard.network.ReputationClient
import id.chatguard.scoring.ExplainedReport
import id.chatguard.scoring.PlainLanguageExplainer
import id.chatguard.scoring.RiskScorer
import id.chatguard.ui.SettingsPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface SafeInspectUiState {
    data object Loading : SafeInspectUiState
    data class Error(val message: String) : SafeInspectUiState
    data class Result(val report: AnalysisReport, val explained: ExplainedReport) : SafeInspectUiState
}

class SafeInspectActivity : ComponentActivity() {

    private var uiState by mutableStateOf<SafeInspectUiState>(SafeInspectUiState.Loading)

    private val settingsPreferences: SettingsPreferences by lazy {
        SettingsPreferences(applicationContext)
    }

    private val reputationClient: ReputationClient by lazy {
        val dao = ChatGuardDatabase.getInstance(applicationContext).reputationCacheDao()
        ReputationClient(
            baseUrlProvider = { settingsPreferences.getServerUrl() },
            cacheDao = dao
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    SafeInspectScreen(
                        state = uiState,
                        onClose = { finish() }
                    )
                }
            }
        }
        handleIncomingIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntent(intent)
    }

    private fun handleIncomingIntent(intent: Intent?) {
        val uri = extractTargetUri(intent)
        if (uri == null) {
            uiState = SafeInspectUiState.Error("Tidak ada file yang dipilih untuk diperiksa.")
            return
        }

        uiState = SafeInspectUiState.Loading
        lifecycleScope.launch {
            uiState = withContext(Dispatchers.IO) {
                inspectUriSafely(uri)
            }
        }
    }

    private suspend fun inspectUriSafely(uri: Uri): SafeInspectUiState {
        val displayName = DownloadWatcherService.resolveDisplayName(contentResolver, uri)
            ?.ifBlank { null }
            ?: "shared_file"

        val tempFile = DownloadWatcherService.createTempCopyFile(cacheDir, displayName)
        return try {
            val copied = DownloadWatcherService.copyUriToTempFile(
                resolver = contentResolver,
                uri = uri,
                destFile = tempFile,
                maxBytes = MAX_INSPECT_BYTES
            )
            if (!copied || !tempFile.exists() || tempFile.length() == 0L) {
                return SafeInspectUiState.Error(
                    "File tidak dapat dibaca atau melebihi batas ukuran 100 MB."
                )
            }

            val rawInspection = FileAnalyzerDispatcher.inspect(tempFile)
            val inspection = if (rawInspection.fileName != displayName) {
                rawInspection.copy(fileName = displayName)
            } else {
                rawInspection
            }

            val allowlist = OfficialCertAllowlist.load(applicationContext)
            val reputation = reputationClient.check(
                sha256 = inspection.sha256,
                urls = inspection.extractedUrls,
                certSha256 = inspection.certSha256
            )

            val report = RiskScorer.evaluate(
                inspection = inspection,
                reputation = reputation,
                allowlist = allowlist,
                fromChat = true
            )
            val explained = PlainLanguageExplainer.explain(report, settingsPreferences.getLocale())
            SafeInspectUiState.Result(report = report, explained = explained)
        } catch (_: Exception) {
            SafeInspectUiState.Error("Gagal memeriksa file. Silakan coba lagi.")
        } finally {
            tempFile.delete()
        }
    }

    private fun extractTargetUri(intent: Intent?): Uri? {
        if (intent == null) return null
        return when (intent.action) {
            Intent.ACTION_VIEW -> intent.data
            Intent.ACTION_SEND -> {
                IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
                    ?: intent.clipData?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.uri
                    ?: intent.data
            }
            else -> intent.data
        }
    }

    companion object {
        const val MAX_INSPECT_BYTES = 100L * 1024L * 1024L // 100 MB
    }
}

@Composable
private fun SafeInspectScreen(
    state: SafeInspectUiState,
    onClose: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        contentAlignment = Alignment.Center
    ) {
        when (state) {
            is SafeInspectUiState.Loading -> {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    CircularProgressIndicator()
                    Text(
                        text = "Memeriksa keamanan file...",
                        style = MaterialTheme.typography.bodyLarge
                    )
                }
            }

            is SafeInspectUiState.Error -> {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF3E0))
                ) {
                    Column(
                        modifier = Modifier.padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text(
                            text = "Pemeriksaan Tidak Dapat Dilanjutkan",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = state.message,
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Button(onClick = onClose, modifier = Modifier.align(Alignment.End)) {
                            Text("Tutup")
                        }
                    }
                }
            }

            is SafeInspectUiState.Result -> {
                val (badgeBg, badgeText) = when (state.report.verdict) {
                    Verdict.AMAN -> Color(0xFFE8F5E9) to Color(0xFF1B5E20)
                    Verdict.MENCURIGAKAN -> Color(0xFFFFF8E1) to Color(0xFFE65100)
                    Verdict.BERBAHAYA -> Color(0xFFFFEBEE) to Color(0xFFB71C1C)
                }

                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(badgeBg, RoundedCornerShape(12.dp))
                            .padding(16.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = state.report.verdict.name,
                            color = badgeText,
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Skor: ${state.report.score}/100",
                            color = badgeText,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold
                        )
                    }

                    Text(
                        text = state.explained.title,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )

                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Text(
                                text = "File: ${state.report.fileName}",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = "Jenis: ${state.report.fileType.name} | SHA-256: ${state.report.sha256.take(12)}...",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Text(
                                text = "Apa yang Ditemukan",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = state.explained.whatInside,
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "Dampak & Saran",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = state.explained.impact,
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }

                    if (state.report.signals.isNotEmpty()) {
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Text(
                                    text = "Sinyal Teknis",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.Bold
                                )
                                state.report.signals.forEach { signal ->
                                    Text(
                                        text = "• ${signal.code} (+${signal.weight}): ${signal.detail}",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                            }
                        }
                    }

                    Button(
                        onClick = onClose,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Tutup")
                    }
                }
            }
        }
    }
}
