package id.chatguard.ui

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
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
fun SettingsScreen(
    currentServerUrl: String,
    currentLanguage: String,
    onSaveServerUrl: (String) -> Boolean,
    onResetServerUrl: () -> String,
    onLanguageChange: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val isId = currentLanguage != SettingsPreferences.LANG_ENGLISH
    var urlInput by remember(currentServerUrl) { mutableStateOf(currentServerUrl) }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var isError by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = if (isId) "Pengaturan ChatGuard" else "ChatGuard Settings",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
            )
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = if (isId) "Bahasa / Language" else "Language / Bahasa",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = currentLanguage != SettingsPreferences.LANG_ENGLISH,
                        onClick = { onLanguageChange(SettingsPreferences.LANG_INDONESIAN) },
                        label = { Text("Bahasa Indonesia") }
                    )
                    FilterChip(
                        selected = currentLanguage == SettingsPreferences.LANG_ENGLISH,
                        onClick = { onLanguageChange(SettingsPreferences.LANG_ENGLISH) },
                        label = { Text("English") }
                    )
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
            )
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = if (isId) "URL Server Reputasi" else "Reputation Server URL",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = if (isId) {
                        "Gunakan HTTPS (atau HTTP hanya untuk localhost / 127.0.0.1 / 10.0.2.2)."
                    } else {
                        "Use HTTPS (or HTTP only for localhost / 127.0.0.1 / 10.0.2.2)."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = urlInput,
                    onValueChange = {
                        urlInput = it
                        statusMessage = null
                        isError = false
                    },
                    singleLine = true,
                    isError = isError,
                    label = { Text(if (isId) "Alamat Server" else "Server Address") },
                    modifier = Modifier.fillMaxWidth()
                )
                statusMessage?.let { msg ->
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = msg,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (isError) Color(0xFFC62828) else Color(0xFF2E7D32)
                    )
                }
                Spacer(modifier = Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            val trimmed = urlInput.trim()
                            if (SettingsValidator.isValidServerUrl(trimmed) && onSaveServerUrl(trimmed)) {
                                urlInput = trimmed
                                isError = false
                                statusMessage = if (isId) "URL server disimpan." else "Server URL saved."
                            } else {
                                isError = true
                                statusMessage = if (isId) {
                                    "URL tidak valid. Harus HTTPS atau HTTP lokal."
                                } else {
                                    "Invalid URL. Must be HTTPS or local HTTP."
                                }
                            }
                        }
                    ) {
                        Text(if (isId) "Simpan" else "Save")
                    }
                    OutlinedButton(
                        onClick = {
                            val defaultUrl = onResetServerUrl()
                            urlInput = defaultUrl
                            isError = false
                            statusMessage = if (isId) "Dikembalikan ke default." else "Reset to default."
                        }
                    ) {
                        Text(if (isId) "Reset Default" else "Reset Default")
                    }
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
            )
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = if (isId) "Privasi & Tanpa Telemetri" else "Privacy & Zero Telemetry",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = if (isId) {
                        "ChatGuard tidak pernah mengirim isi pesan chat atau file Anda. Pemeriksaan reputasi hanya mengirim hash SHA-256 dan URL mencurigakan, dan laporan hasil keliru hanya dikirim jika Anda menyetujuinya secara eksplisit."
                    } else {
                        "ChatGuard never sends your chat messages or file contents. Reputation checks only send SHA-256 hashes and suspicious URLs, and incorrect-result reports are sent only after your explicit consent."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
