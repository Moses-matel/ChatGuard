package id.chatguard.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import id.chatguard.R

@Composable
fun PrivacyAgreementScreen(
    isIndonesian: Boolean,
    onAgreeAndActivateAll: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Spacer(modifier = Modifier.height(8.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                Image(
                    painter = painterResource(id = R.drawable.chatguard_logo),
                    contentDescription = "ChatGuard",
                    contentScale = ContentScale.Crop,
                    modifier = Modifier
                        .size(56.dp)
                        .clip(RoundedCornerShape(14.dp))
                )
                Spacer(modifier = Modifier.width(14.dp))
                Column {
                    Text(
                        text = if (isIndonesian) "Selamat Datang di ChatGuard" else "Welcome to ChatGuard",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = if (isIndonesian) {
                            "Persetujuan Privasi & Keamanan Lokal"
                        } else {
                            "Privacy Agreement & Local Protection"
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color(0xFFEFF6FF))
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = if (isIndonesian) {
                            "Disclaimer Privasi Utama"
                        } else {
                            "Privacy-First Disclaimer"
                        },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF1E3A8A)
                    )
                    Text(
                        text = if (isIndonesian) {
                            "Privasi Anda adalah hal yang sangat penting. ChatGuard TIDAK meminta hak akses yang berbau privasi data pribadi (kami tidak mengakses daftar kontak, galeri/foto pribadi, lokasi, atau merekam/mengirim isi percakapan chat Anda ke mana pun)."
                        } else {
                            "Your privacy is essential. ChatGuard does NOT request personal-data permissions (we never access contacts, private photos, location, or store/send your chat messages anywhere)."
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = Color(0xFF1E293B)
                    )
                    Text(
                        text = if (isIndonesian) {
                            "Seluruh proses deteksi file berbahaya dan pembelajaran pola ancaman dilakukan 100% secara lokal di perangkat Anda."
                        } else {
                            "All threat detection and pattern learning run 100% locally on your device."
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = Color(0xFF0F172A)
                    )
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = if (isIndonesian) {
                            "Izin yang akan diaktifkan untuk perlindungan penuh:"
                        } else {
                            "Permissions activated for full protection:"
                        },
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    BulletLine(
                        if (isIndonesian) "• Pop-up Overlay: Menampilkan kartu peringatan langsung saat melihat file berisiko."
                        else "• Overlay Pop-up: Shows warning cards directly when viewing risky files."
                    )
                    BulletLine(
                        if (isIndonesian) "• Akses Notifikasi & Layar Chat: Mendeteksi nama file mencurigakan di WhatsApp/Telegram sebelum diunduh."
                        else "• Notification & Chat Screen Access: Detects risky filenames in WhatsApp/Telegram before download."
                    )
                    BulletLine(
                        if (isIndonesian) "• Folder Unduhan (SAF): Memeriksa file yang baru masuk tanpa meminta akses ke seluruh penyimpanan."
                        else "• Downloads Folder (SAF): Inspects newly saved files without broad storage access."
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = if (isIndonesian) {
                            "Catatan: Sesuai aturan keamanan Android, setelah Anda menekan Setuju, sistem akan membuka halaman izin secara berurutan agar Anda tinggal mengaktifkannya."
                        } else {
                            "Note: Per Android security rules, after you agree, Android will guide you through each system permission toggle in sequence."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Spacer(modifier = Modifier.height(4.dp))

            Button(
                onClick = onAgreeAndActivateAll,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
            ) {
                Text(
                    text = if (isIndonesian) {
                        "Setuju & Aktifkan Semua Izin"
                    } else {
                        "Agree & Activate All Permissions"
                    },
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

@Composable
private fun BulletLine(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurface
    )
}
