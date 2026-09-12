package dev.cyphernova.mobileops.modules.tier0

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.telephony.CellInfo
import android.telephony.CellInfoCdma
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoTdscdma
import android.telephony.CellInfoWcdma
import android.telephony.CellIdentityLte
import android.telephony.CellIdentityNr
import android.telephony.TelephonyManager
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.core.radio.CellularIntel
import dev.cyphernova.mobileops.core.radio.CellularIntel.Generation
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.Executors
import kotlin.coroutines.resume

/**
 * Enumerates the cellular cells the modem can hear.
 *
 * This is the survey that works when nothing else does. No WiFi in range, no network to join, no
 * data session required — the modem is already measuring every base station around it and the
 * platform will hand the list over for the price of a location permission.
 *
 * What it is for, in an assessment: establishing which operators cover a site, whether a 2G
 * carrier is still live there, and recording the serving cell so a repeat visit can tell a
 * stable environment from one that has changed. The last of those is how a rogue base station
 * gets noticed — not by catching it in the act, but by having a baseline it fails to match.
 */
class CellularSurveyModule : PentestModule {
    override val id = "t0.cell.survey"
    override val title = "Cellular survey"
    override val description =
        "Enumerates every cell the modem can hear — operators, generations, identifiers and " +
            "signal. Needs no WiFi and no data session; works anywhere with coverage."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.PASSIVE
    override val category = ModuleCategory.RADIO
    override val requiredPermissions = listOf(Manifest.permission.ACCESS_FINE_LOCATION)

    /** One cell, flattened out of the platform's per-generation class hierarchy. */
    private data class Cell(
        val generation: Generation,
        val mcc: String?,
        val mnc: String?,
        val identifier: String,
        val areaCode: String,
        val channel: String,
        val dbm: Int,
        val registered: Boolean,
    ) {
        val operator: String get() = CellularIntel.describeOperator(mcc, mnc)
    }

    @SuppressLint("MissingPermission")
    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val telephony = context.androidContext
            .getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            ?: return ModuleOutcome.Blocked("This device has no telephony service.")

        if (telephony.phoneType == TelephonyManager.PHONE_TYPE_NONE) {
            return ModuleOutcome.Blocked(
                "No cellular radio on this device — it is WiFi-only.",
            )
        }

        // getAllCellInfo hands back a cache that, on most modems, holds only the serving cell.
        // requestCellInfoUpdate forces a fresh measurement, and that is what brings the
        // neighbours back — which is the whole point of surveying rather than just asking where
        // the phone is attached.
        val fresh = requestUpdate(telephony)
        val cached = runCatching { telephony.allCellInfo }.getOrNull().orEmpty()
        val raw = (fresh.orEmpty() + cached).distinctBy(::identityOf)

        if (raw.isEmpty()) {
            return ModuleOutcome.Failed(
                "The modem returned no cells. Location services must be on device-wide, and " +
                    "airplane mode switched off.",
            )
        }

        val cells = raw.mapNotNull(::flatten)
        if (cells.isEmpty()) {
            return ModuleOutcome.Failed("The modem reported cells in a form this build cannot read.")
        }

        emitCensus(telephony, cells, emit)
        emitNeighbours(cells, emit)
        emitServingCell(cells, emit)
        emitDowngradeExposure(cells, emit)

        return ModuleOutcome.Completed("${cells.size} cell(s) audible.")
    }

    private suspend fun emitCensus(
        telephony: TelephonyManager,
        cells: List<Cell>,
        emit: suspend (Finding) -> Unit,
    ) {
        val byGeneration = cells.groupingBy { it.generation.label }.eachCount()
        val operators = cells.map { it.operator }.distinct()
        val simOperator = runCatching { telephony.networkOperatorName }.getOrNull().orEmpty()

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.INFO,
                title = "Cellular: ${cells.size} cell(s) audible",
                subject = "Cellular environment",
                detail = buildString {
                    append("Generations in range: ")
                    append(byGeneration.entries.sortedByDescending { it.value }
                        .joinToString { "${it.value}× ${it.key}" })
                    append(". Operators: ")
                    append(operators.joinToString())
                    if (simOperator.isNotBlank()) append(". This handset is on $simOperator")
                    append(".")
                },
                data = mapOf(
                    "cell_count" to cells.size.toString(),
                    "generations" to byGeneration.entries.joinToString { "${it.key}=${it.value}" },
                    "operators" to operators.joinToString(),
                    "serving_operator" to simOperator,
                ),
            ),
        )
    }

    /**
     * The registered cell gets its own finding because its identifiers are the baseline. A cell
     * ID, tracking area and channel recorded at a site are what a later visit is compared against.
     */
    private suspend fun emitServingCell(cells: List<Cell>, emit: suspend (Finding) -> Unit) {
        val serving = cells.firstOrNull { it.registered } ?: return
        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.INFO,
                title = "Serving cell: ${serving.operator}",
                subject = serving.identifier,
                detail = "${serving.generation.label} on ${serving.operator}. " +
                    "Cell ${serving.identifier}, area ${serving.areaCode}, channel ${serving.channel}, " +
                    "${serving.dbm} dBm (${CellularIntel.quality(serving.dbm, serving.generation)}).",
                data = mapOf(
                    "generation" to serving.generation.label,
                    "operator" to serving.operator,
                    "mcc" to serving.mcc.orEmpty(),
                    "mnc" to serving.mnc.orEmpty(),
                    "cell_id" to serving.identifier,
                    "area_code" to serving.areaCode,
                    "channel" to serving.channel,
                    "dbm" to serving.dbm.toString(),
                ),
            ),
        )
    }

    private suspend fun emitDowngradeExposure(cells: List<Cell>, emit: suspend (Finding) -> Unit) {
        val generations = cells.map { it.generation }.toSet()
        val exposure = CellularIntel.downgradeExposure(generations) ?: return
        val legacy = cells.filter { it.generation.rank in 2..3 }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = if (generations.any { it.rank == 2 }) Severity.MEDIUM else Severity.LOW,
                title = "Legacy cellular generation in range",
                subject = "Cellular environment",
                detail = exposure + " Carriers heard: " +
                    legacy.joinToString { "${it.generation.label} ${it.identifier} (${it.operator})" } +
                    ".",
                data = mapOf(
                    "legacy_count" to legacy.size.toString(),
                    "generations" to generations.joinToString { it.label },
                ),
            ),
        )
    }

    /**
     * Asks the modem to measure again rather than reporting what it last cached.
     *
     * Added in Android 10 and rate-limited by the platform, so a null result means "no fresh
     * measurement this time" rather than a failure — the cached list still stands in.
     */
    @SuppressLint("MissingPermission")
    private suspend fun requestUpdate(telephony: TelephonyManager): List<CellInfo>? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        return withTimeoutOrNull(UPDATE_TIMEOUT_MS) {
            suspendCancellableCoroutine { continuation ->
                val executor = Executors.newSingleThreadExecutor()
                continuation.invokeOnCancellation { executor.shutdownNow() }
                val callback = object : TelephonyManager.CellInfoCallback() {
                    override fun onCellInfo(cellInfo: MutableList<CellInfo>) {
                        if (continuation.isActive) continuation.resume(cellInfo.toList())
                    }

                    override fun onError(errorCode: Int, detail: Throwable?) {
                        if (continuation.isActive) continuation.resume(null)
                    }
                }
                val requested = runCatching { telephony.requestCellInfoUpdate(executor, callback) }
                if (requested.isFailure && continuation.isActive) continuation.resume(null)
            }
        }
    }

    /** Cells are merged across the cached and fresh lists, so they need comparing by identity. */
    private fun identityOf(info: CellInfo): String = runCatching {
        info.cellIdentity.toString()
    }.getOrDefault(info.toString())

    /**
     * Neighbours are reported separately from the serving cell because they are what a survey
     * adds over simply asking the phone where it is attached — and an empty list is itself worth
     * saying, since it means the modem would not measure rather than that nothing is there.
     */
    private suspend fun emitNeighbours(cells: List<Cell>, emit: suspend (Finding) -> Unit) {
        val neighbours = cells.filterNot { it.registered }
        if (neighbours.isEmpty()) {
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "No neighbour cells reported",
                    subject = "Cellular environment",
                    detail = "Only the serving cell was returned. Android rate-limits cell " +
                        "measurements and many modems report no neighbours while idle, so this " +
                        "is a handset limit rather than an empty band.",
                    data = mapOf("neighbour_count" to "0"),
                ),
            )
            return
        }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.INFO,
                title = "${neighbours.size} neighbour cell(s)",
                subject = "Cellular environment",
                detail = "Cells measured but not attached to: " +
                    neighbours.joinToString {
                        "${it.generation.label} ${it.identifier} (${it.operator}, ${it.dbm} dBm)"
                    } +
                    ". Handover candidates from this position.",
                data = mapOf(
                    "neighbour_count" to neighbours.size.toString(),
                    "neighbours" to neighbours.joinToString { "${it.identifier}@${it.dbm}dBm" },
                ),
            ),
        )
    }

    /**
     * The platform models each generation with its own identity and signal classes that share no
     * interface, so reading them means naming each one. Every accessor is guarded: which fields
     * a modem populates varies by device, and several were only added to the API later.
     */
    private fun flatten(info: CellInfo): Cell? = runCatching {
        val registered = info.isRegistered
        // A subjectless `when`: the 5G and TD-SCDMA classes only exist from Android 10, so each
        // needs an API guard alongside its type check, which a `when (info)` cannot express.
        when {
            info is CellInfoLte -> {
                val identity: CellIdentityLte = info.cellIdentity
                Cell(
                    generation = Generation.LTE,
                    mcc = identity.mccString,
                    mnc = identity.mncString,
                    identifier = identity.ci.takeIf { it != Int.MAX_VALUE }?.toString() ?: "unknown",
                    areaCode = identity.tac.takeIf { it != Int.MAX_VALUE }?.toString() ?: "unknown",
                    channel = "EARFCN ${identity.earfcn}, PCI ${identity.pci}",
                    dbm = info.cellSignalStrength.dbm,
                    registered = registered,
                )
            }

            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && info is CellInfoNr -> {
                val identity = info.cellIdentity as CellIdentityNr
                Cell(
                    generation = Generation.NR,
                    mcc = identity.mccString,
                    mnc = identity.mncString,
                    identifier = identity.nci.takeIf { it != Long.MAX_VALUE }?.toString() ?: "unknown",
                    areaCode = identity.tac.takeIf { it != Int.MAX_VALUE }?.toString() ?: "unknown",
                    channel = "NR-ARFCN ${identity.nrarfcn}, PCI ${identity.pci}",
                    dbm = info.cellSignalStrength.dbm,
                    registered = registered,
                )
            }

            info is CellInfoWcdma -> Cell(
                generation = Generation.WCDMA,
                mcc = info.cellIdentity.mccString,
                mnc = info.cellIdentity.mncString,
                identifier = info.cellIdentity.cid.takeIf { it != Int.MAX_VALUE }?.toString() ?: "unknown",
                areaCode = info.cellIdentity.lac.takeIf { it != Int.MAX_VALUE }?.toString() ?: "unknown",
                channel = "UARFCN ${info.cellIdentity.uarfcn}",
                dbm = info.cellSignalStrength.dbm,
                registered = registered,
            )

            info is CellInfoGsm -> Cell(
                generation = Generation.GSM,
                mcc = info.cellIdentity.mccString,
                mnc = info.cellIdentity.mncString,
                identifier = info.cellIdentity.cid.takeIf { it != Int.MAX_VALUE }?.toString() ?: "unknown",
                areaCode = info.cellIdentity.lac.takeIf { it != Int.MAX_VALUE }?.toString() ?: "unknown",
                channel = "ARFCN ${info.cellIdentity.arfcn}",
                dbm = info.cellSignalStrength.dbm,
                registered = registered,
            )

            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && info is CellInfoTdscdma -> Cell(
                generation = Generation.TDSCDMA,
                mcc = info.cellIdentity.mccString,
                mnc = info.cellIdentity.mncString,
                identifier = info.cellIdentity.cid.takeIf { it != Int.MAX_VALUE }?.toString() ?: "unknown",
                areaCode = info.cellIdentity.lac.takeIf { it != Int.MAX_VALUE }?.toString() ?: "unknown",
                channel = "UARFCN ${info.cellIdentity.uarfcn}",
                dbm = info.cellSignalStrength.dbm,
                registered = registered,
            )

            info is CellInfoCdma -> Cell(
                generation = Generation.CDMA,
                // CDMA has no MCC/MNC; it identifies networks by system and network ID instead.
                mcc = null,
                mnc = null,
                identifier = info.cellIdentity.basestationId.toString(),
                areaCode = "SID ${info.cellIdentity.systemId}/NID ${info.cellIdentity.networkId}",
                channel = "CDMA",
                dbm = info.cellSignalStrength.dbm,
                registered = registered,
            )

            else -> null
        }
    }.getOrNull()

    private companion object {
        /** The platform rate-limits these; waiting longer does not produce a result. */
        const val UPDATE_TIMEOUT_MS = 8_000L
    }
}
