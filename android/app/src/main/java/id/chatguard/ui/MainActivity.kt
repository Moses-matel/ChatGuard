package id.chatguard.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import id.chatguard.stage2.DownloadWatcherService
import id.chatguard.stage2.SafeInspectActivity
import id.chatguard.stage2.StorageMode
import id.chatguard.stage2.StorageModeResolver

class MainActivity : ComponentActivity() {

    private lateinit var settingsPreferences: SettingsPreferences

    private var statusState by mutableStateOf(
        OnboardingStatus(
            notificationAccessEnabled = false,
            overlayPermissionGranted = false,
            safFolderSelected = false,
            postNotificationsGranted = true,
            safFolderCount = 0
        )
    )

    private val safTreeLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri: Uri? ->
        if (uri != null) {
            try {
                contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            } catch (_: Exception) {
            }
            settingsPreferences.setSafFolderUri(uri)
            refreshStatus()
            startProtectionService()
        }
    }

    private val inspectFileLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            val intent = Intent(this, SafeInspectActivity::class.java).apply {
                action = Intent.ACTION_VIEW
                data = uri
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(intent)
        }
    }

    private val postNotificationsLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        refreshStatus()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settingsPreferences = SettingsPreferences(this)
        refreshStatus()

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    ChatGuardMainScreen()
                }
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun ChatGuardMainScreen() {
        var selectedTab by remember { mutableIntStateOf(0) }
        var language by remember { mutableStateOf(settingsPreferences.getLanguage()) }
        var serverUrl by remember { mutableStateOf(settingsPreferences.getServerUrl()) }
        val isId = language != SettingsPreferences.LANG_ENGLISH

        val lifecycleOwner = LocalLifecycleOwner.current
        DisposableEffect(lifecycleOwner) {
            val observer = LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_RESUME) {
                    refreshStatus()
                }
            }
            lifecycleOwner.lifecycle.addObserver(observer)
            onDispose {
                lifecycleOwner.lifecycle.removeObserver(observer)
            }
        }

        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            text = "ChatGuard",
                            fontWeight = FontWeight.Bold
                        )
                    }
                )
            },
            bottomBar = {
                NavigationBar {
                    NavigationBarItem(
                        selected = selectedTab == 0,
                        onClick = { selectedTab = 0 },
                        icon = { Text("🛡️") },
                        label = { Text(if (isId) "Beranda" else "Home") }
                    )
                    NavigationBarItem(
                        selected = selectedTab == 1,
                        onClick = { selectedTab = 1 },
                        icon = { Text("⚙️") },
                        label = { Text(if (isId) "Pengaturan" else "Settings") }
                    )
                }
            }
        ) { innerPadding ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
                    .verticalScroll(rememberScrollState())
            ) {
                if (selectedTab == 0) {
                    StatusDashboardCard(
                        status = statusState,
                        storageMode = StorageModeResolver.resolveForContext(this@MainActivity),
                        isId = isId
                    )
                    OnboardingScreen(
                        status = statusState,
                        language = language,
                        onRequestNotificationAccess = { openNotificationListenerSettings() },
                        onRequestOverlayPermission = { openOverlaySettings() },
                        onPickSafFolder = { safTreeLauncher.launch(null) },
                        onRequestPostNotifications = { requestPostNotifications() },
                        onStartProtectionService = { startProtectionService() },
                        onInspectFileClick = { inspectFileLauncher.launch(arrayOf("*/*")) }
                    )
                } else {
                    SettingsScreen(
                        currentServerUrl = serverUrl,
                        currentLanguage = language,
                        onSaveServerUrl = { newUrl ->
                            val saved = settingsPreferences.setServerUrl(newUrl)
                            if (saved) {
                                serverUrl = settingsPreferences.getServerUrl()
                            }
                            saved
                        },
                        onResetServerUrl = {
                            settingsPreferences.resetServerUrl()
                            serverUrl = settingsPreferences.getServerUrl()
                            serverUrl
                        },
                        onLanguageChange = { newLang ->
                            settingsPreferences.setLanguage(newLang)
                            language = settingsPreferences.getLanguage()
                        }
                    )
                }
            }
        }
    }

    @Composable
    private fun StatusDashboardCard(
        status: OnboardingStatus,
        storageMode: StorageMode,
        isId: Boolean
    ) {
        val coreReady = status.notificationAccessEnabled || status.safFolderSelected
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            colors = CardDefaults.cardColors(
                containerColor = if (coreReady) {
                    Color(0xFFE8F5E9)
                } else {
                    Color(0xFFFFF3E0)
                }
            )
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = if (coreReady) {
                        if (isId) "Status: Siap Melindungi" else "Status: Ready to Protect"
                    } else {
                        if (isId) "Status: Perlu Pengaturan Awal" else "Status: Setup Needed"
                    },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = if (coreReady) Color(0xFF2E7D32) else Color(0xFFE65100)
                )
                Spacer(modifier = Modifier.height(4.dp))
                val modeText = when (storageMode) {
                    StorageMode.ALL_FILES_WATCHER -> if (isId) "Mode Penyimpanan: Akses Semua File" else "Storage Mode: All Files Watcher"
                    StorageMode.PLAY_SAFE_MEDIASTORE_SAF -> if (isId) "Mode Penyimpanan: Play-Safe (MediaStore + SAF)" else "Storage Mode: Play-Safe (MediaStore + SAF)"
                }
                Text(
                    text = modeText,
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(0xFF374151)
                )
            }
        }
    }

    private fun refreshStatus() {
        val notifEnabled = try {
            NotificationManagerCompat.getEnabledListenerPackages(this).contains(packageName)
        } catch (_: Exception) {
            false
        }
        val overlayGranted = try {
            Settings.canDrawOverlays(this)
        } catch (_: Exception) {
            false
        }
        val persistedSafCount = try {
            contentResolver.persistedUriPermissions.count { it.isReadPermission }
        } catch (_: Exception) {
            0
        }
        val postNotifGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }

        statusState = OnboardingStatus(
            notificationAccessEnabled = notifEnabled,
            overlayPermissionGranted = overlayGranted,
            safFolderSelected = persistedSafCount > 0,
            postNotificationsGranted = postNotifGranted,
            safFolderCount = persistedSafCount
        )
    }

    private fun openNotificationListenerSettings() {
        try {
            startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
        } catch (_: Exception) {
        }
    }

    private fun openOverlaySettings() {
        try {
            val intent = Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                Uri.parse("package:$packageName")
            )
            startActivity(intent)
        } catch (_: Exception) {
        }
    }

    private fun requestPostNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            postNotificationsLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun startProtectionService() {
        val intent = Intent(this, DownloadWatcherService::class.java)
        try {
            ContextCompat.startForegroundService(this, intent)
        } catch (_: Exception) {
            try {
                startService(intent)
            } catch (_: Exception) {
            }
        }
    }
}
