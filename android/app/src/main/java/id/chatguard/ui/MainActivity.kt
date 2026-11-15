package id.chatguard.ui

import android.Manifest
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.TextUtils
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.Image
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import id.chatguard.R
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import id.chatguard.data.ThreatActivityEntry
import id.chatguard.data.ThreatActivityStore
import id.chatguard.data.ThreatLearningStats
import id.chatguard.stage1.ChatScreenAccessibilityService
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

    private var agreementAcceptedState by mutableStateOf(false)
    private var walkthroughCompletedState by mutableStateOf(false)
    private var safeModeEnabledState by mutableStateOf(true)
    private var threatLogsState by mutableStateOf<List<ThreatActivityEntry>>(emptyList())
    private var threatStatsState by mutableStateOf(ThreatLearningStats(0, 0, 0, 0))
    private var blockedFilesState by mutableStateOf<Set<String>>(emptySet())
    private var autoSetupActive by mutableStateOf(false)
    private val promptedAutoSteps = mutableSetOf<String>()

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
        if (autoSetupActive) {
            advanceAutoPermissionSetup()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settingsPreferences = SettingsPreferences(this)
        agreementAcceptedState = settingsPreferences.isAgreementAccepted()
        walkthroughCompletedState = settingsPreferences.isWalkthroughCompleted()
        safeModeEnabledState = settingsPreferences.isSafeModeEnabled()
        refreshStatus()

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    var showSplash by rememberSaveable { mutableStateOf(true) }
                    val isId = settingsPreferences.getLanguage() != SettingsPreferences.LANG_ENGLISH
                    Box(modifier = Modifier.fillMaxSize()) {
                        when {
                            !walkthroughCompletedState -> {
                                WalkthroughScreen(
                                    isIndonesian = isId,
                                    onFinish = {
                                        settingsPreferences.setWalkthroughCompleted(true)
                                        walkthroughCompletedState = true
                                    }
                                )
                            }
                            !agreementAcceptedState -> {
                                PrivacyAgreementScreen(
                                    isIndonesian = isId,
                                    onAgreeAndActivateAll = {
                                        settingsPreferences.setAgreementAccepted(true)
                                        agreementAcceptedState = true
                                        settingsPreferences.setSafeModeEnabled(true)
                                        safeModeEnabledState = true
                                        startProtectionService()
                                        promptedAutoSteps.clear()
                                        autoSetupActive = true
                                        advanceAutoPermissionSetup()
                                    }
                                )
                            }
                            else -> {
                                ChatGuardMainScreen()
                            }
                        }
                        AnimatedVisibility(
                            visible = showSplash,
                            enter = fadeIn(animationSpec = tween(200)),
                            exit = fadeOut(animationSpec = tween(480)) +
                                scaleOut(targetScale = 1.05f, animationSpec = tween(480))
                        ) {
                            ChatGuardSplashOverlay(
                                onFinished = { showSplash = false }
                            )
                        }
                    }
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
                    if (autoSetupActive) {
                        advanceAutoPermissionSetup()
                    }
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
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Image(
                                painter = painterResource(id = R.drawable.chatguard_logo),
                                contentDescription = "ChatGuard",
                                contentScale = ContentScale.Crop,
                                modifier = Modifier
                                    .size(32.dp)
                                    .clip(RoundedCornerShape(8.dp))
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = "ChatGuard",
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = stringResource(id = R.string.app_slogan),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1
                                )
                            }
                        }
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
                        icon = { Text("✨") },
                        label = { Text(if (isId) "Fitur & Update" else "Features") }
                    )
                    NavigationBarItem(
                        selected = selectedTab == 2,
                        onClick = { selectedTab = 2 },
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
                        safeModeEnabled = safeModeEnabledState,
                        storageMode = StorageModeResolver.resolveForContext(this@MainActivity),
                        isId = isId,
                        onToggleSafeMode = { enabled ->
                            settingsPreferences.setSafeModeEnabled(enabled)
                            safeModeEnabledState = enabled
                            if (enabled) {
                                startProtectionService()
                            } else {
                                stopProtectionService()
                            }
                        }
                    )
                    ThreatDashboardSection(
                        stats = threatStatsState,
                        logs = threatLogsState,
                        blockedFiles = blockedFilesState,
                        isIndonesian = isId,
                        onUnblockFile = { fileName ->
                            ThreatActivityStore.unblockFile(this@MainActivity, fileName)
                            refreshStatus()
                        },
                        onClearLogs = {
                            ThreatActivityStore.clearLogs(this@MainActivity)
                            refreshStatus()
                        }
                    )
                    OnboardingScreen(
                        status = statusState,
                        language = language,
                        onRequestNotificationAccess = { openNotificationListenerSettings() },
                        onRequestOverlayPermission = { openOverlaySettings() },
                        onPickSafFolder = { safTreeLauncher.launch(null) },
                        onRequestPostNotifications = { requestPostNotifications() },
                        onStartProtectionService = { startProtectionService() },
                        onInspectFileClick = { inspectFileLauncher.launch(arrayOf("*/*")) },
                        onRequestAccessibilityService = { openAccessibilitySettings() }
                    )
                } else if (selectedTab == 1) {
                    AppInfoAndUpdatesScreen(
                        isIndonesian = isId,
                        onReplayWalkthrough = {
                            walkthroughCompletedState = false
                        }
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
        safeModeEnabled: Boolean,
        storageMode: StorageMode,
        isId: Boolean,
        onToggleSafeMode: (Boolean) -> Unit
    ) {
        val coreReady = status.notificationAccessEnabled || status.safFolderSelected || status.accessibilityServiceEnabled
        val activeAndReady = safeModeEnabled && coreReady
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            colors = CardDefaults.cardColors(
                containerColor = when {
                    !safeModeEnabled -> Color(0xFFF1F5F9)
                    activeAndReady -> Color(0xFFE8F5E9)
                    else -> Color(0xFFFFF3E0)
                }
            )
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = when {
                                !safeModeEnabled -> if (isId) "Mode Aman: NONAKTIF" else "Safe Mode: OFF"
                                activeAndReady -> if (isId) "Mode Aman: AKTIF" else "Safe Mode: ON"
                                else -> if (isId) "Mode Aman: Perlu Izin Awal" else "Safe Mode: Setup Needed"
                            },
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = when {
                                !safeModeEnabled -> Color(0xFF475569)
                                activeAndReady -> Color(0xFF2E7D32)
                                else -> Color(0xFFE65100)
                            }
                        )
                        Text(
                            text = if (safeModeEnabled) {
                                if (isId) "Perlindungan chat & file sedang berjalan" else "Chat & file protection is running"
                            } else {
                                if (isId) "Perlindungan dijeda sementara" else "Protection is paused"
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF475569)
                        )
                    }
                    Switch(
                        checked = safeModeEnabled,
                        onCheckedChange = onToggleSafeMode
                    )
                }
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

        val accessibilityEnabled = isAccessibilityServiceEnabled()

        statusState = OnboardingStatus(
            notificationAccessEnabled = notifEnabled,
            overlayPermissionGranted = overlayGranted,
            safFolderSelected = persistedSafCount > 0,
            postNotificationsGranted = postNotifGranted,
            safFolderCount = persistedSafCount,
            accessibilityServiceEnabled = accessibilityEnabled
        )
        threatLogsState = ThreatActivityStore.getLogs(this)
        threatStatsState = ThreatActivityStore.getStats(this)
        blockedFilesState = ThreatActivityStore.getBlockedFiles(this)
    }

    private fun advanceAutoPermissionSetup() {
        val status = statusState
        when {
            !status.postNotificationsGranted && "post_notif" !in promptedAutoSteps -> {
                promptedAutoSteps += "post_notif"
                requestPostNotifications()
            }
            !status.overlayPermissionGranted && "overlay" !in promptedAutoSteps -> {
                promptedAutoSteps += "overlay"
                openOverlaySettings()
            }
            !status.notificationAccessEnabled && "notif_listener" !in promptedAutoSteps -> {
                promptedAutoSteps += "notif_listener"
                openNotificationListenerSettings()
            }
            !status.accessibilityServiceEnabled && "accessibility" !in promptedAutoSteps -> {
                promptedAutoSteps += "accessibility"
                openAccessibilitySettings()
            }
            !status.safFolderSelected && "saf" !in promptedAutoSteps -> {
                promptedAutoSteps += "saf"
                safTreeLauncher.launch(null)
            }
            else -> {
                autoSetupActive = false
            }
        }
    }

    private fun isAccessibilityServiceEnabled(): Boolean {
        return try {
            val expected = ComponentName(this, ChatScreenAccessibilityService::class.java)
            val enabledServices = Settings.Secure.getString(
                contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            ) ?: return false
            val splitter = TextUtils.SimpleStringSplitter(':')
            splitter.setString(enabledServices)
            while (splitter.hasNext()) {
                val component = ComponentName.unflattenFromString(splitter.next())
                if (component == expected) return true
            }
            false
        } catch (_: Exception) {
            false
        }
    }

    private fun openAccessibilitySettings() {
        try {
            startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
        } catch (_: Exception) {
        }
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
        if (!settingsPreferences.isSafeModeEnabled()) return
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

    private fun stopProtectionService() {
        try {
            stopService(Intent(this, DownloadWatcherService::class.java))
        } catch (_: Exception) {
        }
    }
}
