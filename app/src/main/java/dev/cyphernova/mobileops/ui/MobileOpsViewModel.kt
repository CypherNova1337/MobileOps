package dev.cyphernova.mobileops.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.cyphernova.mobileops.core.capability.CapabilityProbe
import dev.cyphernova.mobileops.core.capability.DeviceCapabilities
import dev.cyphernova.mobileops.core.capture.CaptureController
import dev.cyphernova.mobileops.core.capture.CaptureStatus
import dev.cyphernova.mobileops.core.evidence.EvidenceStore
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.identity.DeviceProfile
import dev.cyphernova.mobileops.core.identity.DeviceProfiles
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.tls.InterceptController
import dev.cyphernova.mobileops.core.tls.TrustStatus
import dev.cyphernova.mobileops.core.tls.TrustStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import dev.cyphernova.mobileops.core.module.Blocker
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.ModuleRegistry
import dev.cyphernova.mobileops.core.module.ModuleRunner
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.core.target.Target
import dev.cyphernova.mobileops.core.target.TargetSelection
import dev.cyphernova.mobileops.modules.tier0.WifiRadio
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.launch
import java.io.File

/** What the UI knows about one module right now. */
data class ModuleState(
    val module: PentestModule,
    val blocker: Blocker?,
    val running: Boolean = false,
    val lastOutcome: ModuleOutcome? = null,
)

class MobileOpsViewModel(application: Application) : AndroidViewModel(application) {

    private val probe = CapabilityProbe(application)
    private val evidenceStore = EvidenceStore(File(application.filesDir, "evidence"))
    private val runner = ModuleRunner(evidenceStore)
    private val radio = WifiRadio(application)

    private val _capabilities = MutableStateFlow(DeviceCapabilities.UNKNOWN)
    val capabilities: StateFlow<DeviceCapabilities> = _capabilities.asStateFlow()

    private val _running = MutableStateFlow<Set<String>>(emptySet())
    val runningModules: StateFlow<Set<String>> = _running.asStateFlow()

    private val _outcomes = MutableStateFlow<Map<String, ModuleOutcome>>(emptyMap())
    val outcomes: StateFlow<Map<String, ModuleOutcome>> = _outcomes.asStateFlow()

    private val _networks = MutableStateFlow<List<Target.Network>>(emptyList())
    val networks: StateFlow<List<Target.Network>> = _networks.asStateFlow()

    private val _scanning = MutableStateFlow(false)
    val scanning: StateFlow<Boolean> = _scanning.asStateFlow()

    /** Hosts typed in by hand, kept apart from discovered ones so a sweep never erases them. */
    private val _manualHosts = MutableStateFlow<List<Target.Host>>(emptyList())

    private val _selectedKeys = MutableStateFlow<Set<String>>(emptySet())
    val selectedKeys: StateFlow<Set<String>> = _selectedKeys.asStateFlow()

    val findings: StateFlow<List<Finding>> = evidenceStore.findings
    val captureStatus: StateFlow<CaptureStatus> = CaptureController.status

    private val _profile = MutableStateFlow(DeviceProfiles.PASSTHROUGH)
    val profile: StateFlow<DeviceProfile> = _profile.asStateFlow()

    private val _vpnConsentNeeded = MutableStateFlow(false)
    val vpnConsentNeeded: StateFlow<Boolean> = _vpnConsentNeeded.asStateFlow()

    /**
     * Hosts a sweep turned up, read back out of the evidence log rather than tracked separately —
     * the log is already the record of what was seen, so deriving from it keeps one source of truth.
     */
    val discoveredHosts: StateFlow<List<Target.Host>> = combine(
        evidenceStore.findings,
        _manualHosts,
    ) { findings, manual ->
        val swept = findings
            .filter { it.moduleId == "t0.net.discovery" && it.title.startsWith("Live host") }
            .map { finding ->
                Target.Host(
                    address = finding.subject,
                    hostname = finding.data["hostname"]?.takeIf { it.isNotBlank() },
                )
            }
        (manual + swept).distinctBy { it.address }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val selection: StateFlow<TargetSelection> = combine(
        _selectedKeys,
        _networks,
        discoveredHosts,
    ) { keys, networks, hosts ->
        TargetSelection((networks + hosts).filter { it.key in keys })
    }.stateIn(viewModelScope, SharingStarted.Eagerly, TargetSelection())

    val interceptEnabled: StateFlow<Boolean> = InterceptController.enabled
    val interceptedRequests = InterceptController.requests
    val interceptCounters = InterceptController.counters

    init {
        viewModelScope.launch {
            evidenceStore.load()
            refreshCapabilities()
            scanNetworks()
        }
        // Intercepted requests arrive continuously while a capture runs; mirroring them into the
        // evidence log here keeps a single writer rather than handing the service a second one.
        viewModelScope.launch {
            var recorded = 0
            InterceptController.requests.collect { requests ->
                if (requests.size < recorded) recorded = 0 // the list was cleared
                requests.drop(recorded).forEach { request ->
                    evidenceStore.record(
                        Finding(
                            moduleId = "t0.tls.intercept",
                            observedAtEpochMs = request.observedAtEpochMs,
                            severity = if (request.secrets.isEmpty()) Severity.INFO else Severity.MEDIUM,
                            title = "${request.method} ${request.host}",
                            subject = request.url,
                            detail = if (request.secrets.isEmpty()) {
                                "Read in the clear inside the intercepted flow."
                            } else {
                                "Read in the clear. " + request.secrets.joinToString(" ") {
                                    "${it.kind} (${it.where}): ${it.detail}."
                                }
                            },
                            data = mapOf(
                                "host" to request.host,
                                "method" to request.method,
                                "path" to request.path,
                                "secret_count" to request.secrets.size.toString(),
                            ),
                        ),
                    )
                }
                recorded = requests.size
            }
        }
    }

    fun refreshCapabilities() {
        viewModelScope.launch { _capabilities.value = probe.probe() }
    }

    /** Asks the platform for a fresh scan, then reads whatever it is willing to share. */
    fun scanNetworks() {
        if (_scanning.value) return
        viewModelScope.launch {
            _scanning.value = true
            radio.requestScan()
            delay(SCAN_SETTLE_MS)
            _networks.value = radio.latestResults()
                .sortedByDescending { it.rssiDbm }
                .map { observation ->
                    Target.Network(
                        ssid = observation.ssid,
                        bssid = observation.bssid,
                        frequencyMhz = observation.frequencyMhz,
                        capabilities = observation.capabilities,
                        rssiDbm = observation.rssiDbm,
                    )
                }
            _scanning.value = false
        }
    }

    fun toggleSelection(target: Target) {
        val keys = _selectedKeys.value
        _selectedKeys.value = if (target.key in keys) keys - target.key else keys + target.key
    }

    fun clearSelection() {
        _selectedKeys.value = emptySet()
    }

    fun addManualHost(raw: String) {
        val entries = raw.split(',', '\n', ' ')
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .map { Target.Host(it) }
        if (entries.isEmpty()) return

        _manualHosts.value = (_manualHosts.value + entries).distinctBy { it.address }
        // Typing a host in is an explicit choice, so select it straight away.
        _selectedKeys.value = _selectedKeys.value + entries.map { it.key }
    }

    /** Recomputed on every state change so the reason a module is locked is always current. */
    fun moduleStates(): List<ModuleState> {
        val caps = _capabilities.value
        val targets = selection.value
        val running = _running.value
        val outcomes = _outcomes.value
        return ModuleRegistry.all.map { module ->
            ModuleState(
                module = module,
                blocker = runner.blockerFor(module, getApplication(), caps, targets),
                running = module.id in running,
                lastOutcome = outcomes[module.id],
            )
        }
    }

    fun runModule(module: PentestModule) {
        if (module.id in _running.value) return
        viewModelScope.launch {
            _running.value = _running.value + module.id
            val outcome = runner.run(
                module,
                getApplication(),
                _capabilities.value,
                selection.value,
                _profile.value,
            )
            _outcomes.value = _outcomes.value + (module.id to outcome)
            _running.value = _running.value - module.id
        }
    }

    fun selectProfile(profile: DeviceProfile) {
        _profile.value = profile
    }

    fun requestVpnConsent() {
        _vpnConsentNeeded.value = true
    }

    fun vpnConsentHandled() {
        _vpnConsentNeeded.value = false
    }

    fun clearEvidence() {
        viewModelScope.launch { evidenceStore.clear() }
    }

    fun renderReport(): String = evidenceStore.renderReport()

    /** The CA certificate file, once interception has generated one. */
    fun caCertificateFile(): File? =
        File(File(getApplication<Application>().filesDir, "tls"), "MobileOps-CA.pem")
            .takeIf { it.exists() }

    /** Whether this device already trusts our CA, and whether stale copies are lying around. */
    fun caTrustStatus(): TrustStatus =
        caCertificate()?.let(TrustStore::status) ?: TrustStatus.UNKNOWN

    private fun caCertificate(): X509Certificate? {
        val der = caCertificateDer() ?: return null
        return runCatching {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(der.inputStream()) as X509Certificate
        }.getOrNull()
    }

    /**
     * The CA as raw DER, which is what the system certificate installer expects — it takes the
     * certificate bytes directly rather than a file path.
     */
    fun caCertificateDer(): ByteArray? {
        val pem = caCertificateFile()?.readText() ?: return null
        val body = pem.substringAfter("-----BEGIN CERTIFICATE-----", "")
            .substringBefore("-----END CERTIFICATE-----", "")
            .replace(Regex("\\s"), "")
        if (body.isBlank()) return null
        return runCatching { java.util.Base64.getDecoder().decode(body) }.getOrNull()
    }

    private companion object {
        const val SCAN_SETTLE_MS = 2_500L
    }
}
