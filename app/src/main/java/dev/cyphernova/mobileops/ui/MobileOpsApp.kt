package dev.cyphernova.mobileops.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GpsFixed
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.cyphernova.mobileops.ui.screens.DashboardScreen
import dev.cyphernova.mobileops.ui.screens.TargetsScreen
import dev.cyphernova.mobileops.ui.screens.EvidenceScreen
import dev.cyphernova.mobileops.ui.screens.ModulesScreen

private enum class Destination(val label: String, val icon: ImageVector) {
    DASHBOARD("Device", Icons.Filled.Memory),
    TARGETS("Targets", Icons.Filled.GpsFixed),
    MODULES("Modules", Icons.Filled.Wifi),
    EVIDENCE("Evidence", Icons.Filled.Description),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MobileOpsApp(
    onRequestPermissions: () -> Unit,
    viewModel: MobileOpsViewModel = viewModel(),
) {
    var destination by remember { mutableStateOf(Destination.DASHBOARD) }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = { TopAppBar(title = { Text("MobileOps · ${destination.label}") }) },
        bottomBar = {
            NavigationBar {
                Destination.entries.forEach { entry ->
                    NavigationBarItem(
                        selected = destination == entry,
                        onClick = { destination = entry },
                        icon = { Icon(entry.icon, contentDescription = entry.label) },
                        label = { Text(entry.label) },
                    )
                }
            }
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            when (destination) {
                Destination.DASHBOARD -> DashboardScreen(viewModel, onRequestPermissions)
                Destination.TARGETS -> TargetsScreen(viewModel)
                Destination.MODULES -> ModulesScreen(viewModel)
                Destination.EVIDENCE -> EvidenceScreen(viewModel)
            }
        }
    }
}
