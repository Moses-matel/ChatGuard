package id.chatguard.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SettingsValidationTest {

    @Test
    fun `valid https urls are accepted`() {
        assertTrue(SettingsValidator.isValidServerUrl("https://api.chatguard.id"))
        assertTrue(SettingsValidator.isValidServerUrl("https://api.chatguard.id/"))
        assertTrue(SettingsValidator.isValidServerUrl("https://guard.example.com:8443/api"))
        assertTrue(SettingsValidator.isValidServerUrl("https://sub.domain.co.id"))
    }

    @Test
    fun `http urls for remote hosts are rejected`() {
        assertFalse(SettingsValidator.isValidServerUrl("http://insecure.example.com"))
        assertFalse(SettingsValidator.isValidServerUrl("http://api.chatguard.id"))
        assertFalse(SettingsValidator.isValidServerUrl("http://192.168.1.10:8000"))
    }

    @Test
    fun `http urls for localhost loopback and android emulator are allowed`() {
        assertTrue(SettingsValidator.isValidServerUrl("http://localhost:8000"))
        assertTrue(SettingsValidator.isValidServerUrl("http://localhost"))
        assertTrue(SettingsValidator.isValidServerUrl("http://127.0.0.1:8000"))
        assertTrue(SettingsValidator.isValidServerUrl("http://10.0.2.2:8000"))
        assertTrue(SettingsValidator.isValidServerUrl("http://10.0.2.2"))
    }

    @Test
    fun `blank malformed and non-http schemes are rejected`() {
        assertFalse(SettingsValidator.isValidServerUrl(""))
        assertFalse(SettingsValidator.isValidServerUrl("   "))
        assertFalse(SettingsValidator.isValidServerUrl("not-a-url"))
        assertFalse(SettingsValidator.isValidServerUrl("https://"))
        assertFalse(SettingsValidator.isValidServerUrl("http://"))
        assertFalse(SettingsValidator.isValidServerUrl("file:///etc/passwd"))
        assertFalse(SettingsValidator.isValidServerUrl("javascript:alert(1)"))
        assertFalse(SettingsValidator.isValidServerUrl("ftp://example.com"))
        assertFalse(SettingsValidator.isValidServerUrl("https://invalid host.com"))
    }
}
