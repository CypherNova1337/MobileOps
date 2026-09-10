package dev.cyphernova.mobileops.core.module

import dev.cyphernova.mobileops.modules.tier0.HostDiscoveryModule
import dev.cyphernova.mobileops.modules.tier0.IdentityAuditModule
import dev.cyphernova.mobileops.modules.tier0.PortScanModule
import dev.cyphernova.mobileops.modules.tier0.RogueApModule
import dev.cyphernova.mobileops.modules.tier0.TlsAuditModule
import dev.cyphernova.mobileops.modules.tier0.TlsInterceptModule
import dev.cyphernova.mobileops.modules.tier0.VpnCaptureModule
import dev.cyphernova.mobileops.modules.tier0.WifiSurveyModule
import dev.cyphernova.mobileops.modules.tier1.IdentitySpoofModule
import dev.cyphernova.mobileops.modules.tier1.InterfaceCaptureModule
import dev.cyphernova.mobileops.modules.tier2.MonitorModeModule

/**
 * Every module the app ships. Keeping the list in one place is what lets the UI show the full
 * catalogue — including the modules this device cannot run — with an honest reason attached.
 */
object ModuleRegistry {

    val all: List<PentestModule> = listOf(
        WifiSurveyModule(),
        RogueApModule(),
        HostDiscoveryModule(),
        PortScanModule(),
        TlsAuditModule(),
        VpnCaptureModule(),
        TlsInterceptModule(),
        IdentityAuditModule(),
        InterfaceCaptureModule(),
        IdentitySpoofModule(),
        MonitorModeModule(),
    )
}
