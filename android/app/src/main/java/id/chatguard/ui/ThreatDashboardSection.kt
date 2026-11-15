package id.chatguard.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import id.chatguard.core.model.Verdict
import id.chatguard.data.ThreatActivityEntry
import id.chatguard.data.ThreatLearningStats
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ThreatDashboardSection(
    stats: ThreatLearningStats,
    logs: List<ThreatActivityEntry>,
    blockedFiles: Set<String>,
    isIndonesian: Boolean,
    onUnblockFile: (String) -> Unit,
    onClearLogs: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            StatTile(
                label = if (isIndonesian) "Terdeteksi" else "Detected",
                value = stats.totalDetected.toString(),
                containerColor = Color(0xFFFFF7ED),
                accentColor = Color(0xFFC2410C),
                modifier = Modifier.weight(1f)
            )
            StatTile(
                label = if (isIndonesian) "Diblokir" else "Blocked",
                value = stats.totalBlocked.toString(),
                containerColor = Color(0xFFFEF2F2),
                accentColor = Color(0xFFB91C1C),
                modifier = Modifier.weight(1f)
            )
            StatTile(
                label = if (isIndonesian) "Pola Lokal" else "Learned",
                value = stats.learnedPatternsCount.toString(),
                containerColor = Color(0xFFEFF6FF),
                accentColor = Color(0xFF1D4ED8),
                modifier = Modifier.weight(1f)
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (isIndonesian) "Log Aktivitas & Belajar Ancaman" else "Threat Activity & Learning Log",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = if (isIndonesian) {
                        "Ketuk kartu untuk memahami modus serangan & cara menghindarinya."
                    } else {
                        "Tap any card to learn how the threat works and stay safe."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (logs.isNotEmpty()) {
                TextButton(onClick = onClearLogs) {
                    Text(if (isIndonesian) "Bersihkan" else "Clear")
                }
            }
        }

        if (logs.isEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
                )
            ) {
                Text(
                    text = if (isIndonesian) {
                        "Belum ada aktivitas mencurigakan yang tercatat. ChatGuard aktif memantau dan mempelajari pola ancaman secara lokal di perangkat Anda."
                    } else {
                        "No suspicious activity recorded yet. ChatGuard is actively monitoring and learning threat patterns locally on your device."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(14.dp)
                )
            }
        } else {
            logs.take(15).forEach { entry ->
                ThreatActivityCard(
                    entry = entry,
                    isBlocked = entry.fileName.trim().lowercase(Locale.ROOT) in blockedFiles,
                    isIndonesian = isIndonesian,
                    onUnblockFile = { onUnblockFile(entry.fileName) }
                )
            }
        }
    }
}

@Composable
private fun StatTile(
    label: String,
    value: String,
    containerColor: Color,
    accentColor: Color,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = containerColor)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 10.dp, horizontal = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = value,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = accentColor
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = Color(0xFF374151)
            )
        }
    }
}

@Composable
private fun ThreatActivityCard(
    entry: ThreatActivityEntry,
    isBlocked: Boolean,
    isIndonesian: Boolean,
    onUnblockFile: () -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val timeFormat = remember { SimpleDateFormat("dd MMM, HH:mm", Locale.getDefault()) }
    val timeLabel = remember(entry.timestampMs) {
        if (entry.timestampMs > 0L) timeFormat.format(Date(entry.timestampMs)) else ""
    }

    val badgeColor = when (entry.verdict) {
        Verdict.BERBAHAYA -> Color(0xFFDC2626)
        Verdict.MENCURIGAKAN -> Color(0xFFD97706)
        Verdict.AMAN -> Color(0xFF16A34A)
    }
    val badgeText = when (entry.verdict) {
        Verdict.BERBAHAYA -> if (isIndonesian) "BERBAHAYA" else "DANGEROUS"
        Verdict.MENCURIGAKAN -> if (isIndonesian) "MENCURIGAKAN" else "SUSPICIOUS"
        Verdict.AMAN -> if (isIndonesian) "AMAN" else "SAFE"
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded },
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)
        )
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Surface(
                        color = badgeColor,
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Text(
                            text = badgeText,
                            color = Color.White,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                        )
                    }
                    Text(
                        text = "${entry.sourceLabel} • $timeLabel",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Text(
                    text = entry.actionTaken,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = badgeColor
                )
            }

            Text(
                text = entry.fileName,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )

            Text(
                text = if (expanded) {
                    if (isIndonesian) "Tutup detail ▲" else "Hide details ▲"
                } else {
                    if (isIndonesian) "Lihat alasan, dampak & pelajaran ▼" else "View reason, impact & lesson ▼"
                },
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary
            )

            AnimatedVisibility(visible = expanded) {
                Column(
                    modifier = Modifier.padding(top = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    DetailBlock(
                        header = if (isIndonesian) "Apa yang ditemukan:" else "What was found:",
                        body = entry.whatFound
                    )
                    DetailBlock(
                        header = if (isIndonesian) "Dampak:" else "Impact:",
                        body = entry.impact
                    )
                    DetailBlock(
                        header = if (isIndonesian) "Saran:" else "Advice:",
                        body = entry.advice
                    )
                    if (entry.lessonTip.isNotBlank()) {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFFEF9C3))
                        ) {
                            Text(
                                text = "💡 ${if (isIndonesian) "Belajar dari kasus ini: " else "Lesson: "}${entry.lessonTip}",
                                style = MaterialTheme.typography.bodySmall,
                                color = Color(0xFF713F12),
                                modifier = Modifier.padding(10.dp)
                            )
                        }
                    }
                    if (isBlocked) {
                        Spacer(modifier = Modifier.height(2.dp))
                        OutlinedButton(onClick = onUnblockFile) {
                            Text(if (isIndonesian) "Buka Blokir File Ini" else "Unblock This File")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailBlock(header: String, body: String) {
    Column {
        Text(
            text = header,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = body,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
