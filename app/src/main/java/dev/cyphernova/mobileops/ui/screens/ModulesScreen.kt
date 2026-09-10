package dev.cyphernova.mobileops.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import android.net.VpnService
import androidx.compose.ui.platform.LocalContext
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.ui.MobileOpsViewModel
import dev.cyphernova.mobileops.ui.ModuleState

@Composable
fun ModulesScreen(viewModel: MobileOpsViewModel) {
    // Recomputed against capabilities, selection and run state so lock reasons stay live.
    val capabilities by viewModel.capabilities.collectAsState()
    val selection by viewModel.selection.collectAsState()
    val running by viewModel.runningModules.collectAsState()
    val outcomes by viewModel.outcomes.collectAsState()
    val capture by viewModel.captureStatus.collectAsState()
    val states = remember(capabilities, selection, running, outcomes) { viewModel.moduleStates() }

    LazyColumn(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            val count = selection.targets.size
            Text(
                if (count == 0) {
                    "No targets selected — host modules stay locked."
                } else {
                    "$count target(s) selected: " + selection.targets.joinToString { it.label }
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (capture.running) {
            item { CaptureBanner(capture) }
        }

        items(states, key = { it.module.id }) { state -> ModuleCard(state, viewModel) }
    }
}

/** Live counters while the rootless capture is up. */
@Composable
private fun CaptureBanner(capture: dev.cyphernova.mobileops.core.capture.CaptureStatus) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Capture running", fontWeight = FontWeight.Bold)
            Text(
                "${capture.packets} packets · ${capture.bytes / 1024} KiB · " +
                    "${capture.tcpFlows} TCP / ${capture.udpFlows} UDP flows",
                style = MaterialTheme.typography.bodySmall,
            )
            val established = capture.counters["tcp_established"] ?: 0L
            val syns = capture.counters["tcp_syn_seen"] ?: 0L
            val v6 = capture.counters["ipv6_dropped"] ?: 0L
            Text(
                "TCP $established/$syns established · $v6 IPv6 dropped",
                style = MaterialTheme.typography.bodySmall,
            )
            if (capture.diagnosis.isNotBlank()) {
                Text(
                    capture.diagnosis,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (capture.diagnosis.startsWith("Relay healthy")) {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    } else {
                        MaterialTheme.colorScheme.error
                    },
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
            capture.pcapPath?.let {
                Text(
                    it.substringAfterLast('/'),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ModuleCard(state: ModuleState, viewModel: MobileOpsViewModel) {
    val module = state.module
    val context = LocalContext.current
    // Consent is revocable from system settings, so it is re-read rather than cached.
    val needsVpnConsent = module.id == CAPTURE_MODULE_ID &&
        remember(state.lastOutcome) { VpnService.prepare(context) != null }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(module.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)

            Row(
                Modifier.padding(vertical = 6.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                AssistChip(onClick = {}, label = { Text(module.requiredTier.label) })
                AssistChip(
                    onClick = {},
                    label = { Text(if (module.intrusiveness == Intrusiveness.ACTIVE) "Active" else "Passive") },
                    colors = if (module.intrusiveness == Intrusiveness.ACTIVE) {
                        AssistChipDefaults.assistChipColors(
                            labelColor = MaterialTheme.colorScheme.error,
                        )
                    } else {
                        AssistChipDefaults.assistChipColors()
                    },
                )
            }

            Text(
                module.description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            state.blocker?.let { blocker ->
                Text(
                    "🔒 ${blocker.headline}",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(top = 10.dp),
                )
                Text(
                    blocker.remedy,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            state.lastOutcome?.let { outcome ->
                val (prefix, message) = when (outcome) {
                    is ModuleOutcome.Completed -> "✓" to outcome.summary
                    is ModuleOutcome.Blocked -> "🔒" to outcome.reason
                    is ModuleOutcome.Failed -> "✗" to outcome.reason
                }
                Text(
                    "$prefix $message",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 10.dp),
                )
            }

            Row(
                Modifier.fillMaxWidth().padding(top = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                val capturing = module.id == CAPTURE_MODULE_ID &&
                    viewModel.captureStatus.collectAsState().value.running

                Button(
                    onClick = { viewModel.runModule(module) },
                    enabled = state.blocker == null && !state.running,
                ) {
                    Text(
                        when {
                            state.running -> "Running…"
                            capturing -> "Stop capture"
                            else -> "Run"
                        },
                    )
                }

                if (module.id == CAPTURE_MODULE_ID && needsVpnConsent) {
                    OutlinedButton(onClick = viewModel::requestVpnConsent) {
                        Text("Grant VPN permission")
                    }
                }

                if (state.running) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                }
            }
        }
    }
}

/** The capture module is the one card with extra controls, so its id is named here. */
private const val CAPTURE_MODULE_ID = "t0.capture.vpn"
