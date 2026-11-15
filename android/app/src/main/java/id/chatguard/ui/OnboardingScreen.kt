package id.chatguard.ui

import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

data class OnboardingStatus(
    val notificationAccessEnabled: Boolean,
    val overlayPermissionGranted: Boolean,
    val safFolderSelected: Boolean,
    val postNotificationsGranted: Boolean,
    val safFolderCount: Int,
    val accessibilityServiceEnabled: Boolean = false
)

@Composable
fun OnboardingScreen(
    status: OnboardingStatus,
    language: String,
    onRequestNotificationAccess: () -> Unit,
    onRequestOverlayPermission: () -> Unit,
    onPickSafFolder: () -> Unit,
    onRequestPostNotifications: () -> Unit,
    onStartProtectionService: () -> Unit,
    onInspectFileClick: () -> Unit,
    modifier: Modifier = Modifier,
    onRequestAccessibilityService: () -> Unit = {}
) {
    val isId = language != SettingsPreferences.LANG_ENGLISH

    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(
            text = if (isId) "Perlindungan ChatGuard" else "ChatGuard Protection",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = if (isId) {
                "Aktifkan izin berikut agar ChatGuard dapat memperingatkan Anda sebelum file berbahaya dibuka."
            } else {
                "Enable the permissions below so ChatGuard can warn you before dangerous files are opened."
            },
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        PermissionStepCard(
            stepNumber = 1,
            title = if (isId) "Akses Notifikasi Chat" else "Chat Notification Access",
            description = if (isId) {
                "Mendeteksi nama file mencurigakan pada notifikasi WhatsApp & Telegram secara lokal tanpa menyimpan isi pesan."
            } else {
                "Detects suspicious filenames in WhatsApp & Telegram notifications locally without storing message contents."
            },
            granted = status.notificationAccessEnabled,
            grantedLabel = if (isId) "Aktif" else "Enabled",
            pendingLabel = if (isId) "Belum Aktif" else "Not Enabled",
            actionLabel = if (isId) "Buka Pengaturan Notifikasi" else "Open Notification Settings",
            onAction = onRequestNotificationAccess
        )

        PermissionStepCard(
            stepNumber = 2,
            title = if (isId) "Tampilan Pop-up Peringatan" else "Floating Warning Pop-up",
            description = if (isId) {
                "Menampilkan kartu peringatan langsung di atas layar saat file berisiko terdeteksi (jika tidak aktif, peringatan dikirim lewat notifikasi)."
            } else {
                "Shows warning cards directly on screen when risky files are detected (falls back to high-priority notifications if off)."
            },
            granted = status.overlayPermissionGranted,
            grantedLabel = if (isId) "Diizinkan" else "Granted",
            pendingLabel = if (isId) "Mode Notifikasi" else "Notification Fallback",
            actionLabel = if (isId) "Izinkan Overlay" else "Allow Overlay",
            onAction = onRequestOverlayPermission
        )

        PermissionStepCard(
            stepNumber = 3,
            title = if (isId) "Folder Unduhan (SAF)" else "Downloads Folder (SAF)",
            description = if (isId) {
                "Pilih folder Download / Dokumen WhatsApp menggunakan pemilih folder resmi Android tanpa izin akses semua file."
            } else {
                "Select your Download or WhatsApp Documents folder using Android's standard folder picker (Play-compliant)."
            },
            granted = status.safFolderSelected,
            grantedLabel = if (isId) "${status.safFolderCount} folder dipilih" else "${status.safFolderCount} folder(s) selected",
            pendingLabel = if (isId) "Belum Dipilih" else "Not Selected",
            actionLabel = if (isId) "Pilih Folder" else "Choose Folder",
            onAction = onPickSafFolder
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            PermissionStepCard(
                stepNumber = 4,
                title = if (isId) "Izin Notifikasi Peringatan" else "Alert Notifications",
                description = if (isId) {
                    "Diperlukan Android 13+ untuk menampilkan notifikasi layanan perlindungan dan peringatan cadangan."
                } else {
                    "Required on Android 13+ to show the protection service status and fallback threat alerts."
                },
                granted = status.postNotificationsGranted,
                grantedLabel = if (isId) "Diizinkan" else "Granted",
                pendingLabel = if (isId) "Belum Diizinkan" else "Not Granted",
                actionLabel = if (isId) "Izinkan Notifikasi" else "Allow Notifications",
                onAction = onRequestPostNotifications
            )
        }

        PermissionStepCard(
            stepNumber = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) 5 else 4,
            title = if (isId) "Pantau Layar Chat (Aksesibilitas)" else "Chat Screen Monitor (Accessibility)",
            description = if (isId) {
                "Memunculkan pop-up overlay saat Anda melihat file mencurigakan langsung di dalam chat WhatsApp/Telegram tanpa perlu notifikasi atau download."
            } else {
                "Shows an overlay pop-up when you view suspicious files inside WhatsApp/Telegram chats without notifications or downloading."
            },
            granted = status.accessibilityServiceEnabled,
            grantedLabel = if (isId) "Aktif" else "Enabled",
            pendingLabel = if (isId) "Opsional" else "Optional",
            actionLabel = if (isId) "Buka Pengaturan Aksesibilitas" else "Open Accessibility Settings",
            onAction = onRequestAccessibilityService
        )

        Spacer(modifier = Modifier.height(4.dp))

        Button(
            onClick = onStartProtectionService,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = if (isId) "Mulai / Perbarui Layanan Perlindungan" else "Start / Refresh Protection Service"
            )
        }

        OutlinedButton(
            onClick = onInspectFileClick,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = if (isId) "Periksa File Sekarang" else "Inspect a File Now"
            )
        }
    }
}

@Composable
private fun PermissionStepCard(
    stepNumber: Int,
    title: String,
    description: String,
    granted: Boolean,
    grantedLabel: String,
    pendingLabel: String,
    actionLabel: String,
    onAction: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
        )
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "$stepNumber. $title",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f)
                )
                Text(
                    text = if (granted) grantedLabel else pendingLabel,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = if (granted) Color(0xFF2E7D32) else Color(0xFFED6C02)
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(onClick = onAction) {
                Text(actionLabel)
            }
        }
    }
}
