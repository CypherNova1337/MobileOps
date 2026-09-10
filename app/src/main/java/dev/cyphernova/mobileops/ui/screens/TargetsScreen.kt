package dev.cyphernova.mobileops.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.cyphernova.mobileops.core.target.Target
import dev.cyphernova.mobileops.modules.tier0.ApObservation
import dev.cyphernova.mobileops.modules.tier0.ApSecurityAnalyser
import dev.cyphernova.mobileops.ui.MobileOpsViewModel

/**
 * Pick what to point modules at: a WiFi network from the live scan, a host a sweep turned up,
 * or something typed in by hand.
 */
@Composable
fun TargetsScreen(viewModel: MobileOpsViewModel) {
    val networks by viewModel.networks.collectAsState()
    val hosts by viewModel.discoveredHosts.collectAsState()
    val selected by viewModel.selectedKeys.collectAsState()
    val scanning by viewModel.scanning.collectAsState()

    var manualEntry by remember { mutableStateOf("") }

    LazyColumn(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedButton(onClick = viewModel::scanNetworks, enabled = !scanning) {
                    Text(if (scanning) "Scanning…" else "Scan WiFi")
                }
                if (scanning) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                if (selected.isNotEmpty()) {
                    TextButton(onClick = viewModel::clearSelection) {
                        Text("Clear (${selected.size})")
                    }
                }
            }
        }

        item { SectionHeading("WiFi networks", networks.size) }

        if (networks.isEmpty()) {
            item {
                Hint(
                    if (scanning) {
                        "Scanning…"
                    } else {
                        "No results. WiFi must be on and location enabled device-wide, " +
                            "not just granted to the app."
                    },
                )
            }
        }

        items(networks, key = { it.key }) { network ->
            NetworkRow(
                network = network,
                selected = network.key in selected,
                onToggle = { viewModel.toggleSelection(network) },
            )
        }

        item { SectionHeading("Hosts", hosts.size) }

        if (hosts.isEmpty()) {
            item { Hint("Run the subnet sweep on the Modules tab, or add a host below.") }
        }

        items(hosts, key = { it.key }) { host ->
            HostRow(
                host = host,
                selected = host.key in selected,
                onToggle = { viewModel.toggleSelection(host) },
            )
        }

        item {
            Row(
                Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = manualEntry,
                    onValueChange = { manualEntry = it },
                    label = { Text("Add host or IP") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                OutlinedButton(
                    onClick = {
                        viewModel.addManualHost(manualEntry)
                        manualEntry = ""
                    },
                    enabled = manualEntry.isNotBlank(),
                ) { Text("Add") }
            }
        }
    }
}

@Composable
private fun NetworkRow(network: Target.Network, selected: Boolean, onToggle: () -> Unit) {
    // Reuse the survey module's analyser so the label here and the finding there always agree.
    val profile = remember(network.key, network.capabilities) {
        ApSecurityAnalyser.analyse(
            ApObservation(
                ssid = network.ssid,
                bssid = network.bssid,
                capabilities = network.capabilities,
                frequencyMhz = network.frequencyMhz,
                rssiDbm = network.rssiDbm,
            ),
        )
    }
    val observation = remember(network.key) {
        ApObservation(network.ssid, network.bssid, network.capabilities, network.frequencyMhz, network.rssiDbm)
    }

    SelectableRow(selected = selected, onToggle = onToggle) {
        Text(network.label, fontWeight = FontWeight.SemiBold)
        Text(
            "${profile.encryption.label} · ${observation.band} ch ${observation.channel} · ${observation.rssiLabel}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            network.bssid,
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun HostRow(host: Target.Host, selected: Boolean, onToggle: () -> Unit) {
    SelectableRow(selected = selected, onToggle = onToggle) {
        Text(host.address, fontWeight = FontWeight.SemiBold, fontFamily = FontFamily.Monospace)
        host.hostname?.let {
            Text(
                it,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun SelectableRow(
    selected: Boolean,
    onToggle: () -> Unit,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onToggle),
        colors = if (selected) {
            CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        } else {
            CardDefaults.cardColors()
        },
    ) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(checked = selected, onCheckedChange = { onToggle() })
            Column(Modifier.padding(start = 4.dp, top = 8.dp, bottom = 8.dp)) { content() }
        }
    }
}

@Composable
private fun SectionHeading(title: String, count: Int) {
    Text(
        "$title ($count)",
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(top = 12.dp, bottom = 2.dp),
    )
}

@Composable
private fun Hint(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}
