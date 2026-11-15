package id.chatguard.ui

import android.content.Context
import android.content.SharedPreferences
import android.net.Uri
import java.net.URI
import java.util.Locale

object SettingsValidator {
    private val ALLOWED_HTTP_HOSTS = setOf("localhost", "127.0.0.1", "10.0.2.2")
    private val HOST_PATTERN = Regex("""^[A-Za-z0-9.-]+$""")

    fun isValidServerUrl(url: String): Boolean {
        if (url.isBlank() || url != url.trim()) return false
        if (url.any { it.isWhitespace() }) return false

        val parsed = try {
            URI(url)
        } catch (_: Exception) {
            return false
        }

        val scheme = parsed.scheme?.lowercase(Locale.ROOT) ?: return false
        if (scheme != "https" && scheme != "http") return false
        if (parsed.userInfo != null) return false

        val host = parsed.host?.lowercase(Locale.ROOT) ?: return false
        if (host.isBlank() || host.startsWith(".") || host.endsWith(".") || host.startsWith("-") || host.endsWith("-")) {
            return false
        }
        if (!HOST_PATTERN.matches(host)) return false

        val port = parsed.port
        if (port != -1 && port !in 1..65535) return false

        if (scheme == "http" && host !in ALLOWED_HTTP_HOSTS) {
            return false
        }

        return true
    }
}

class SettingsPreferences(context: Context) {

    private val prefs: SharedPreferences = context.applicationContext
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getServerUrl(): String {
        val stored = prefs.getString(KEY_SERVER_URL, DEFAULT_SERVER_URL).orEmpty()
        return if (SettingsValidator.isValidServerUrl(stored)) stored else DEFAULT_SERVER_URL
    }

    fun setServerUrl(url: String): Boolean {
        val trimmed = url.trim()
        if (!SettingsValidator.isValidServerUrl(trimmed)) {
            return false
        }
        prefs.edit().putString(KEY_SERVER_URL, trimmed).apply()
        return true
    }

    fun resetServerUrl() {
        prefs.edit().putString(KEY_SERVER_URL, DEFAULT_SERVER_URL).apply()
    }

    fun getLanguage(): String {
        val lang = prefs.getString(KEY_LANGUAGE, LANG_INDONESIAN) ?: LANG_INDONESIAN
        return if (lang == LANG_ENGLISH) LANG_ENGLISH else LANG_INDONESIAN
    }

    fun setLanguage(language: String) {
        val normalized = if (language.equals(LANG_ENGLISH, ignoreCase = true)) {
            LANG_ENGLISH
        } else {
            LANG_INDONESIAN
        }
        prefs.edit().putString(KEY_LANGUAGE, normalized).apply()
    }

    fun getLocale(): Locale {
        return if (getLanguage() == LANG_ENGLISH) {
            Locale("en", "US")
        } else {
            Locale("in", "ID")
        }
    }

    fun getSafFolderUri(): Uri? {
        val raw = prefs.getString(KEY_SAF_FOLDER_URI, null) ?: return null
        return try {
            Uri.parse(raw)
        } catch (_: Exception) {
            null
        }
    }

    fun setSafFolderUri(uri: Uri?) {
        if (uri == null) {
            prefs.edit().remove(KEY_SAF_FOLDER_URI).apply()
        } else {
            prefs.edit().putString(KEY_SAF_FOLDER_URI, uri.toString()).apply()
        }
    }

    fun isAgreementAccepted(): Boolean {
        return prefs.getBoolean(KEY_AGREEMENT_ACCEPTED, false)
    }

    fun setAgreementAccepted(accepted: Boolean) {
        prefs.edit().putBoolean(KEY_AGREEMENT_ACCEPTED, accepted).apply()
    }

    fun isSafeModeEnabled(): Boolean {
        return prefs.getBoolean(KEY_SAFE_MODE_ENABLED, true)
    }

    fun setSafeModeEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_SAFE_MODE_ENABLED, enabled).apply()
    }

    fun isWalkthroughCompleted(): Boolean {
        return prefs.getBoolean(KEY_WALKTHROUGH_COMPLETED, false)
    }

    fun setWalkthroughCompleted(completed: Boolean) {
        prefs.edit().putBoolean(KEY_WALKTHROUGH_COMPLETED, completed).apply()
    }

    companion object {
        private const val PREFS_NAME = "chatguard_settings"
        private const val KEY_SERVER_URL = "server_url"
        private const val KEY_LANGUAGE = "language"
        private const val KEY_SAF_FOLDER_URI = "saf_folder_uri"
        private const val KEY_AGREEMENT_ACCEPTED = "agreement_accepted"
        private const val KEY_SAFE_MODE_ENABLED = "safe_mode_enabled"
        private const val KEY_WALKTHROUGH_COMPLETED = "walkthrough_completed"

        const val DEFAULT_SERVER_URL = "https://api.chatguard.id"
        const val LANG_INDONESIAN = "in"
        const val LANG_ENGLISH = "en"
    }
}
