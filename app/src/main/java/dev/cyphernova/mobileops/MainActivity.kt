package dev.cyphernova.mobileops

import android.Manifest
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.cyphernova.mobileops.ui.MobileOpsApp
import dev.cyphernova.mobileops.ui.MobileOpsViewModel
import dev.cyphernova.mobileops.ui.theme.MobileOpsTheme

class MainActivity : ComponentActivity() {

    private val permissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { }

    private val vpnConsentLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        requestScanPermissions()
        setContent {
            MobileOpsTheme {
                val model: MobileOpsViewModel = viewModel()
                val consentNeeded by model.vpnConsentNeeded.collectAsState()

                // VpnService.prepare returns an Intent the first time; the system dialog it opens
                // is the only way an app can be granted a TUN, and it must come from an Activity.
                LaunchedEffect(consentNeeded) {
                    if (consentNeeded) {
                        VpnService.prepare(this@MainActivity)?.let(vpnConsentLauncher::launch)
                        model.vpnConsentHandled()
                    }
                }

                MobileOpsApp(
                    onRequestPermissions = ::requestScanPermissions,
                    viewModel = model,
                )
            }
        }
    }

    private fun requestScanPermissions() {
        val permissions = buildList {
            add(Manifest.permission.ACCESS_FINE_LOCATION)
            // Android 13 introduced a scanning-specific permission that does not imply location,
            // and a separate opt-in for the capture service's ongoing notification.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // BLE scanning became its own permission in Android 12.
                add(Manifest.permission.BLUETOOTH_SCAN)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.NEARBY_WIFI_DEVICES)
                add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        permissionLauncher.launch(permissions.toTypedArray())
    }
}
