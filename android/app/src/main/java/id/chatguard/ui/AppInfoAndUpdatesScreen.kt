package id.chatguard.ui

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
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

private data class AppFeatureItem(
    val icon: String,
    val title: String,
    val description: String
)

private data class UpdateNoteItem(
    val version: String,
    val date: String,
    val highlights: List<String>
)

@Composable
fun AppInfoAndUpdatesScreen(
    isIndonesian: Boolean,
    onReplayWalkthrough: () -> Unit,
    modifier: Modifier = Modifier
) {
    val features = if (isIndonesian) {
        listOf(
            AppFeatureItem(
                icon = "🛡️",
                title = "Mode Aman ON/OFF Sekali Ketuk",
                description = "Aktifkan atau jeda seluruh pemantauan notifikasi, layar chat, dan pemindaian unduhan kapan saja langsung dari Beranda."
            ),
            AppFeatureItem(
                icon = "💬",
                title = "Deteksi Pra-Unduh (Notifikasi & Layar Chat)",
                description = "Mendeteksi ekstensi ganda (.pdf.apk), file eksekusi berbahaya, dan kata pancingan penipuan di WhatsApp & Telegram sebelum file diunduh."
            ),
            AppFeatureItem(
                icon = "🔍",
                title = "Inspeksi Isi File Lokal (Stage 2)",
                description = "Memeriksa header file asli (magic bytes), izin berbahaya pada APK, JavaScript/OpenAction di PDF, macro Office, serta arsip ZIP/RAR."
            ),
            AppFeatureItem(
                icon = "🚫",
                title = "Blokir & Hapus Cepat",
                description = "Tandai file berbahaya ke daftar blokir lokal dan hapus salinan yang terlanjur tersimpan di folder Download/WhatsApp Documents."
            ),
            AppFeatureItem(
                icon = "📚",
                title = "Log Aktivitas & Belajar Ancaman",
                description = "Riwayat serangan ramah pengguna dengan penjelasan alasan, dampak, saran, sinyal teknis, dan pelajaran singkat di setiap kejadian."
            ),
            AppFeatureItem(
                icon = "🔒",
                title = "100% Privasi Terjaga",
                description = "Berjalan lokal di perangkat. Tidak meminta akses kontak, foto pribadi, atau menyimpan/mengirim isi pesan chat Anda."
            )
        )
    } else {
        listOf(
            AppFeatureItem(
                icon = "🛡️",
                title = "One-Tap Safe Mode ON/OFF",
                description = "Enable or pause notification monitoring, chat screen inspection, and download scanning anytime from Home."
            ),
            AppFeatureItem(
                icon = "💬",
                title = "Pre-Download Detection (Notifications & Chat Screen)",
                description = "Detects double extensions (.pdf.apk), risky executables, and phishing lures in WhatsApp & Telegram before downloading."
            ),
            AppFeatureItem(
                icon = "🔍",
                title = "Local File Content Inspection (Stage 2)",
                description = "Inspects real file headers (magic bytes), dangerous APK permissions, PDF JavaScript/OpenAction, Office macros, and archives."
            ),
            AppFeatureItem(
                icon = "🚫",
                title = "Quick Block & Delete",
                description = "Add risky files to your local blocklist and remove downloaded copies from Download or WhatsApp Documents."
            ),
            AppFeatureItem(
                icon = "📚",
                title = "Threat Activity & Learning Log",
                description = "User-friendly threat history with plain-language causes, impacts, advice, technical signals, and safety lessons."
            ),
            AppFeatureItem(
                icon = "🔒",
                title = "100% Privacy-First Local Processing",
                description = "Runs locally on your phone without accessing contacts, private photos, or storing/uploading chat messages."
            )
        )
    }

    val updates = if (isIndonesian) {
        listOf(
            UpdateNoteItem(
                version = "v1.2.0 (Terbaru)",
                date = "15 Nov 2026",
                highlights = listOf(
                    "Tombol ON/OFF Mode Aman di Beranda untuk mengaktifkan/menjeda perlindungan.",
                    "Walkthrough interaktif saat pertama kali membuka aplikasi.",
                    "Tab Fitur & Update berisi daftar fitur lengkap dan catatan pembaruan.",
                    "Anti-spam scroll (cooldown 10 menit) & kotak Sinyal Teknis di pop-up overlay."
                )
            ),
            UpdateNoteItem(
                version = "v1.1.0",
                date = "15 Nov 2026",
                highlights = listOf(
                    "Pemantau Layar Chat (Accessibility) untuk WhatsApp & Telegram.",
                    "Pop-up lengkap (Apa yang ditemukan, Dampak, Saran) + tombol Ya, Blokir & Hapus.",
                    "Dashboard Log Aktivitas & Belajar Ancaman + Persetujuan Privasi awal.",
                    "Logo resmi ChatGuard, animasi pembuka, dan slogan."
                )
            ),
            UpdateNoteItem(
                version = "v1.0.0",
                date = "15 Nov 2026",
                highlights = listOf(
                    "Rilis awal ChatGuard: Stage 1 Notifikasi, Stage 2 Safe Inspect, dan Mode Hybrid Server Reputasi."
                )
            )
        )
    } else {
        listOf(
            UpdateNoteItem(
                version = "v1.2.0 (Latest)",
                date = "Nov 15, 2026",
                highlights = listOf(
                    "Safe Mode ON/OFF switch on Home dashboard.",
                    "First-launch interactive walkthrough.",
                    "Features & Updates tab with release notes.",
                    "Smart 10-minute scroll cooldown & Technical Signals box on Stage 1 overlay."
                )
            ),
            UpdateNoteItem(
                version = "v1.1.0",
                date = "Nov 15, 2026",
                highlights = listOf(
                    "Chat Screen Monitor (Accessibility) for WhatsApp & Telegram.",
                    "Detailed Stage 1 overlay + Yes, Block & Delete action.",
                    "Threat Activity & Learning Log dashboard + Privacy Agreement screen.",
                    "Official ChatGuard logo, splash animation, and slogan."
                )
            ),
            UpdateNoteItem(
                version = "v1.0.0",
                date = "Nov 15, 2026",
                highlights = listOf(
                    "Initial ChatGuard release: Stage 1 Notification Guard, Stage 2 Safe Inspect, and Hybrid Reputation API support."
                )
            )
        )
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            text = if (isIndonesian) "Informasi Pembaruan (Updates)" else "Updates Information",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold
        )

        updates.forEachIndexed { index, note ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (index == 0) Color(0xFFEFF6FF)
                    else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
                )
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Surface(
                            color = if (index == 0) Color(0xFF1D4ED8) else Color(0xFF475569),
                            shape = RoundedCornerShape(6.dp)
                        ) {
                            Text(
                                text = note.version,
                                color = Color.White,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                            )
                        }
                        Text(
                            text = note.date,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    note.highlights.forEach { item ->
                        Text(
                            text = "• $item",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF1E293B)
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = if (isIndonesian) "Fitur-Fitur Aplikasi ChatGuard" else "ChatGuard App Features",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold
        )

        features.forEach { feature ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)
                )
            ) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.Top
                ) {
                    Text(
                        text = feature.icon,
                        style = MaterialTheme.typography.headlineSmall
                    )
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(
                            text = feature.title,
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = feature.description,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        OutlinedButton(
            onClick = onReplayWalkthrough,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(if (isIndonesian) "Putar Ulang Panduan Awal (Walkthrough)" else "Replay Walkthrough Guide")
        }
    }
}
