package dev.cyphernova.mobileops.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.clickable
import androidx.compose.material3.RadioButton
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.identity.DeviceProfiles
import dev.cyphernova.mobileops.ui.MobileOpsViewModel

/**
 * The first thing the operator sees: what this handset can actually do, stated plainly, so
 * nobody wastes time discovering a module was never going to run.
 */
@Composable
fun DashboardScreen(viewModel: MobileOpsViewModel, onRequestPermissions: () -> Unit) {
    val capabilities by viewModel.capabilities.collectAsState()

    LazyColumn(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Card {
                Column(Modifier.padding(16.dp)) {
                    Text(
                        capabilities.tier.label,
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(capabilities.tier.blurb, style = MaterialTheme.typography.bodyMedium)
                    HorizontalDivider(Modifier.padding(vertical = 12.dp))
                    Fact("Device", capabilities.deviceLabel)
                    Fact("Root", capabilities.rootDetail)
                    Fact("Monitor mode", capabilities.monitorModeDetail)
                    Fact(
                        "WiFi interfaces",
                        capabilities.wifiInterfaces.joinToString().ifBlank { "none visible" },
                    )
                    Fact(
                        "Scan budget",
                        if (capabilities.scanThrottled) {
                            "${capabilities.scanBudgetPerWindow} scans / 2 min (Android 10+ throttle)"
                        } else {
                            "unthrottled"
                        },
                    )
                }
            }
        }

        item {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedButton(onClick = viewModel::refreshCapabilities) { Text("Re-probe") }
                OutlinedButton(onClick = onRequestPermissions) { Text("Permissions") }
            }
        }

        if (capabilities.usbAdapters.isNotEmpty()) {
            item {
                Card {
                    Column(Modifier.padding(16.dp)) {
                        Text("USB adapters", fontWeight = FontWeight.Bold)
                        capabilities.usbAdapters.forEach { adapter ->
                            Text(
                                "${adapter.chipset} (${adapter.identifier})",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                modifier = Modifier.padding(top = 8.dp),
                            )
                            adapter.productName?.let {
                                Text(it, style = MaterialTheme.typography.bodySmall)
                            }
                            Text(
                                if (adapter.claimedByKernel) {
                                    "✓ claimed by the kernel · driver ${adapter.driver}"
                                } else {
                                    "✗ not claimed · needs ${adapter.driver}"
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = if (adapter.claimedByKernel) {
                                    MaterialTheme.colorScheme.onSurface
                                } else {
                                    MaterialTheme.colorScheme.error
                                },
                            )
                            adapter.blockers(capabilities.rooted).forEach { blocker ->
                                Text(
                                    "• $blocker",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(start = 8.dp, top = 2.dp),
                                )
                            }
                        }
                    }
                }
            }
        }

        item {
            val profile by viewModel.profile.collectAsState()
            Card {
                Column(Modifier.padding(16.dp)) {
                    Text("Identity profile", fontWeight = FontWeight.Bold)
                    Text(
                        "What this device presents to a network under test. Applying a profile " +
                            "needs root — on a stock device this selection only tells the identity " +
                            "audit what to compare against.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    HorizontalDivider(Modifier.padding(vertical = 12.dp))
                    DeviceProfiles.builtIn.forEach { candidate ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clickable { viewModel.selectProfile(candidate) }
                                .padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(
                                selected = profile.id == candidate.id,
                                onClick = { viewModel.selectProfile(candidate) },
                            )
                            Column(Modifier.padding(start = 4.dp)) {
                                Text(candidate.label, fontWeight = FontWeight.SemiBold)
                                Text(
                                    candidate.description,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }
        }

        item {
            Card {
                Column(Modifier.padding(16.dp)) {
                    Text("Tier ceiling", fontWeight = FontWeight.Bold)
                    Text(
                        "Modules above this device's tier stay visible but locked. Nothing here " +
                            "pretends a capability the hardware will not give up.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    HorizontalDivider(Modifier.padding(vertical = 12.dp))
                    Tier.entries.forEach { tier ->
                        val reachable = tier.satisfiedBy(capabilities.tier)
                        Text(
                            "${if (reachable) "✓" else "✗"}  ${tier.label}",
                            fontWeight = if (reachable) FontWeight.SemiBold else FontWeight.Normal,
                            color = if (reachable) {
                                MaterialTheme.colorScheme.onSurface
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                        )
                        Text(
                            tier.blurb,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(start = 20.dp, bottom = 8.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun Fact(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(end = 8.dp),
        )
        Text(value, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
    }
}
