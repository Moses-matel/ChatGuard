package id.chatguard.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import id.chatguard.R

private data class WalkthroughPage(
    val emoji: String,
    val title: String,
    val description: String,
    val highlight: String,
    val showLogo: Boolean = false
)

@Composable
fun WalkthroughScreen(
    isIndonesian: Boolean,
    onFinish: () -> Unit,
    modifier: Modifier = Modifier
) {
    val pages = remember(isIndonesian) {
        if (isIndonesian) {
            listOf(
                WalkthroughPage(
                    emoji = "🛡️",
                    title = "Selamat Datang di ChatGuard",
                    description = "Aman dulu sebelum buka—deteksi file berbahaya secara pintar sebelum diunduh.",
                    highlight = "Pelindung khusus untuk file penipuan (.apk palsu, PDF berbahaya, resi/undangan palsu) yang sering beredar di chat.",
                    showLogo = true
                ),
                WalkthroughPage(
                    emoji = "💬",
                    title = "Peringatan Langsung di Layar Chat",
                    description = "Saat Anda menerima notifikasi atau melihat file mencurigakan di WhatsApp & Telegram, pop-up peringatan langsung muncul sebelum Anda mengunduhnya.",
                    highlight = "Tidak perlu menunggu file terunduh atau terpasang terlebih dahulu."
                ),
                WalkthroughPage(
                    emoji = "🚫",
                    title = "Pahami Risiko, Sinyal Teknis & Blokir",
                    description = "Setiap peringatan menjelaskan Apa yang ditemukan, Dampak jika dibuka, Saran aman, serta Sinyal Teknis yang terdeteksi.",
                    highlight = "Anda bisa langsung menekan 'Ya, Blokir & Hapus' untuk mengamankan file dalam satu ketukan."
                ),
                WalkthroughPage(
                    emoji = "🔒",
                    title = "Belajar Ancaman & 100% Lokal",
                    description = "Semua aktivitas serangan tercatat rapi di Dashboard agar Anda bisa belajar mengenali modus penipuan terbaru.",
                    highlight = "Privasi terjaga: tidak ada kontak, galeri, atau isi pesan chat Anda yang disimpan atau dikirim."
                )
            )
        } else {
            listOf(
                WalkthroughPage(
                    emoji = "🛡️",
                    title = "Welcome to ChatGuard",
                    description = "Safe before you open—smartly detect dangerous files before downloading.",
                    highlight = "Built to catch phishing lures (fake .apk invites, risky PDFs, disguised receipts) sent via chat.",
                    showLogo = true
                ),
                WalkthroughPage(
                    emoji = "💬",
                    title = "Instant Alerts Right on Chat Screen",
                    description = "Whenever a suspicious filename appears in WhatsApp or Telegram notifications or on screen, an overlay warning appears immediately.",
                    highlight = "Stay aware before downloading or opening anything risky."
                ),
                WalkthroughPage(
                    emoji = "🚫",
                    title = "Clear Reasons, Technical Signals & Block",
                    description = "Each warning explains what was found, potential impact, safe advice, and technical signals.",
                    highlight = "Tap 'Yes, Block & Delete' to block the file and remove local copies right away."
                ),
                WalkthroughPage(
                    emoji = "🔒",
                    title = "Learn Threats & 100% Local Privacy",
                    description = "Review every detected event in the Threat Activity & Learning Log on your home dashboard.",
                    highlight = "Privacy first: your contacts, photos, and chat messages are never stored or uploaded."
                )
            )
        }
    }

    var currentIndex by remember { mutableIntStateOf(0) }
    val isLast = currentIndex == pages.lastIndex

    Surface(
        modifier = modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "${currentIndex + 1} / ${pages.size}",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                TextButton(onClick = onFinish) {
                    Text(if (isIndonesian) "Lewati" else "Skip")
                }
            }

            AnimatedContent(
                targetState = pages[currentIndex],
                transitionSpec = { fadeIn() togetherWith fadeOut() },
                label = "walkthrough_slide"
            ) { page ->
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    if (page.showLogo) {
                        Image(
                            painter = painterResource(id = R.drawable.chatguard_logo),
                            contentDescription = "ChatGuard Logo",
                            contentScale = ContentScale.Crop,
                            modifier = Modifier
                                .size(120.dp)
                                .clip(RoundedCornerShape(28.dp))
                        )
                    } else {
                        Box(
                            modifier = Modifier
                                .size(96.dp)
                                .clip(CircleShape)
                                .background(Color(0xFFEFF6FF)),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(text = page.emoji, fontSize = 44.sp)
                        }
                    }

                    Text(
                        text = page.title,
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.Center
                    )

                    Text(
                        text = page.description,
                        style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Center,
                        color = MaterialTheme.colorScheme.onSurface
                    )

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFF1F5F9))
                    ) {
                        Text(
                            text = page.highlight,
                            style = MaterialTheme.typography.bodyMedium,
                            textAlign = TextAlign.Center,
                            color = Color(0xFF334155),
                            modifier = Modifier.padding(16.dp)
                        )
                    }
                }
            }

            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    pages.indices.forEach { idx ->
                        val active = idx == currentIndex
                        Box(
                            modifier = Modifier
                                .width(if (active) 24.dp else 8.dp)
                                .height(8.dp)
                                .clip(CircleShape)
                                .background(
                                    if (active) MaterialTheme.colorScheme.primary
                                    else MaterialTheme.colorScheme.outlineVariant
                                )
                        )
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    if (currentIndex > 0) {
                        OutlinedButton(
                            onClick = { currentIndex-- },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(if (isIndonesian) "Kembali" else "Back")
                        }
                    }
                    Button(
                        onClick = {
                            if (isLast) onFinish() else currentIndex++
                        },
                        modifier = Modifier.weight(1.4f)
                    ) {
                        Text(
                            text = if (isLast) {
                                if (isIndonesian) "Mulai Sekarang" else "Get Started"
                            } else {
                                if (isIndonesian) "Lanjut" else "Next"
                            },
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    }
}
