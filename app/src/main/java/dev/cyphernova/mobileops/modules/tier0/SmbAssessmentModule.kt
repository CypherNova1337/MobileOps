package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.core.smb.Ntlm
import dev.cyphernova.mobileops.core.smb.Smb
import dev.cyphernova.mobileops.core.smb.SrvSvc
import dev.cyphernova.mobileops.core.target.HostHarvest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Answers the SMB questions instead of listing them.
 *
 * The port scan can only say that 445 is open, so it says "confirm signing is required and v1 is
 * disabled" — which hands the actual work back to the operator. All three of those questions are
 * answerable before authentication, and this asks them:
 *
 *  - **Is SMB1 still enabled?** An SMB1-only negotiate either gets an SMB1 answer or it does not.
 *  - **Is signing required?** The negotiate response states the policy in a flag. Signing merely
 *    *enabled* is the setting that lets a relay through; signing *required* is the one that stops
 *    it.
 *  - **Will it talk to nobody?** An anonymous session setup is one request, presents no password
 *    and guesses nothing, so there is no account to lock out.
 *
 * The NTLM challenge that comes back on the way is worth as much as any of them: it names the
 * host, its domain, its DNS names and often its OS build, to a caller who has proved nothing.
 */
class SmbAssessmentModule : PentestModule {
    override val id = "t0.net.smb"
    override val title = "SMB exposure"
    override val description =
        "Negotiates SMB without authenticating: reports whether SMB1 is still enabled, whether " +
            "signing is required or merely enabled, and whether the server accepts a null " +
            "session. Records the host, domain and OS the NTLM challenge discloses on the way."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val category = ModuleCategory.NETWORK
    override val requiresTarget = false

    // Picks its own hosts out of whatever answered on 139 or 445.
    override val prerequisites = listOf("t0.net.discovery")

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val hosts = targets(context)
        if (hosts.isEmpty()) {
            return ModuleOutcome.Blocked(
                "No SMB hosts. Select a target, or run host discovery or the port scan first so " +
                    "this can pick up whatever answered on 139 or 445.",
            )
        }

        var reachable = 0
        var weak = 0

        hosts.forEach { host ->
            val assessment = assess(host) ?: return@forEach
            reachable++

            emit(summary(host, assessment))

            if (assessment.smb1Enabled) {
                weak++
                emit(smb1Finding(host))
            }
            if (assessment.negotiated != null && !assessment.negotiated.signingRequired) {
                weak++
                emit(signingFinding(host, assessment.negotiated))
            }
            if (assessment.nullSession) {
                weak++
                emit(nullSessionFinding(host, assessment.challenge))
                if (assessment.shares.isNotEmpty()) {
                    weak++
                    emit(shareFinding(host, assessment.shares))
                } else {
                    // Reported rather than dropped: an empty share list and a refused enumeration
                    // look identical in a report, and only one of them is the server holding firm.
                    emit(shareLookupFinding(host, assessment.shareLookupStoppedAt))
                }
            }
            assessment.challenge?.let { emit(disclosureFinding(host, it)) }
        }

        if (reachable == 0) {
            return ModuleOutcome.Completed(
                "Tried ${hosts.size} host(s); none completed an SMB negotiate.",
            )
        }
        return ModuleOutcome.Completed(
            "$reachable host(s) answered SMB; $weak weakness(es) found.",
        )
    }

    /**
     * Selected hosts where the operator chose some, otherwise every host the run has already seen
     * answering on an SMB port. Running this against a whole segment is the normal case — the
     * question is which machines are misconfigured, and that is not known in advance.
     */
    private fun targets(context: ModuleContext): List<String> {
        val selected = context.targets.hosts()
        if (selected.isNotEmpty()) return selected.distinct()
        val known = HostHarvest.hostsIn(context.priorFindings).map { it.address }.toSet()
        return context.priorFindings
            .filter { finding ->
                val ports = finding.data["open_ports"].orEmpty()
                    .split(',').mapNotNull { it.trim().toIntOrNull() } +
                    listOfNotNull(finding.data["port"]?.trim()?.toIntOrNull())
                ports.any { it in SMB_PORTS }
            }
            .mapNotNull { finding ->
                finding.data["host"]?.trim()?.takeIf { it.isNotBlank() }
                    ?: finding.subject.substringBefore(':').trim().takeIf { it.isNotBlank() }
            }
            .filter { it in known }
            .distinct()
    }

    private data class Assessment(
        val port: Int,
        val smb1Enabled: Boolean,
        val negotiated: Smb.Negotiated?,
        val challenge: Ntlm.Challenge?,
        val nullSession: Boolean,
        val shares: List<SrvSvc.Share> = emptyList(),
        val shareLookupStoppedAt: String? = null,
    )

    private suspend fun assess(host: String): Assessment? = withContext(Dispatchers.IO) {
        val port = SMB_PORTS.firstOrNull { reachable(host, it) } ?: return@withContext null

        // Each question gets its own connection. A server that dislikes one of them closes the
        // socket, and that must not cost the answers to the others.
        val smb1 = exchange(host, port) { Smb.smb1NegotiateRequest() }
            ?.let { Smb.dialectFamilyOf(it) == Smb.Family.SMB1 } ?: false

        var negotiated: Smb.Negotiated? = null
        var challenge: Ntlm.Challenge? = null
        var nullSession = false
        var shares: List<SrvSvc.Share> = emptyList()
        var shareStop: String? = null

        runCatching {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
                socket.soTimeout = READ_TIMEOUT_MS

                val negotiateReply = roundTrip(socket, Smb.smb2NegotiateRequest())
                negotiated = negotiateReply?.let { Smb.parseNegotiateResponse(it) }
                if (negotiated == null) return@use

                val setupReply = roundTrip(
                    socket,
                    Smb.smb2SessionSetupRequest(Ntlm.negotiate(), messageId = 1),
                ) ?: return@use
                challenge = Ntlm.parseChallenge(setupReply)

                // Only worth asking once the server has actually offered NTLM. Without a
                // challenge there is nothing to answer and a "no" would mean nothing.
                if (challenge == null) return@use
                val sessionId = sessionIdOf(setupReply)
                val authReply = roundTrip(
                    socket,
                    Smb.smb2SessionSetupRequest(
                        Ntlm.authenticateAnonymous(),
                        messageId = 2,
                        sessionId = sessionId,
                    ),
                ) ?: return@use
                nullSession = Smb.statusOf(authReply) == Smb.STATUS_SUCCESS

                // Only worth asking once the session exists. "Null session accepted" is a
                // statement about what might be reachable; the share list is what is.
                if (nullSession) {
                    val attempt = enumerateShares(socket, host, sessionId)
                    shares = attempt.shares
                    shareStop = attempt.stoppedAt
                }
            }
        }

        if (!smb1 && negotiated == null) return@withContext null
        Assessment(port, smb1, negotiated, challenge, nullSession, shares, shareStop)
    }

    /** How far the share enumeration got, and what stopped it. */
    private data class ShareAttempt(
        val shares: List<SrvSvc.Share> = emptyList(),
        val stoppedAt: String? = null,
    ) {
        val succeeded: Boolean get() = stoppedAt == null
    }

    /**
     * Asks the server what it is sharing, over the `srvsvc` pipe on IPC$.
     *
     * Four steps, each of which can legitimately fail on a hardened host: connect to IPC$, open
     * the pipe, bind to the interface, make the call. A refusal at any of them is an answer — the
     * null session exists but cannot enumerate — so none of them is an error, and every one of
     * them says which it was rather than returning an empty list that reads as "no shares".
     */
    private fun enumerateShares(socket: Socket, host: String, sessionId: Long): ShareAttempt {
        val tree = roundTrip(
            socket,
            Smb.smb2TreeConnectRequest(host, "IPC$", messageId = 3, sessionId = sessionId),
        ) ?: return ShareAttempt(stoppedAt = "IPC\$ tree connect got no reply")
        val treeStatus = Smb.statusOf(tree)
        if (treeStatus != Smb.STATUS_SUCCESS) {
            return ShareAttempt(stoppedAt = "IPC\$ tree connect refused (${status(treeStatus)})")
        }
        val treeId = Smb.treeIdOf(tree)

        val create = roundTrip(
            socket,
            Smb.smb2CreateRequest("srvsvc", messageId = 4, sessionId = sessionId, treeId = treeId),
        ) ?: return ShareAttempt(stoppedAt = "opening the srvsvc pipe got no reply")
        val fileId = Smb.fileIdOf(create)
            ?: return ShareAttempt(
                stoppedAt = "the srvsvc pipe would not open (${status(Smb.statusOf(create))})",
            )

        val bind = roundTrip(
            socket,
            Smb.smb2PipeTransceiveRequest(
                fileId, SrvSvc.bindRequest(), messageId = 5, sessionId, treeId,
            ),
        ) ?: return ShareAttempt(stoppedAt = "the RPC bind got no reply")
        val bindOutput = Smb.ioctlOutput(bind)
            ?: return ShareAttempt(
                stoppedAt = "the RPC bind returned nothing (${status(Smb.statusOf(bind))})",
            )
        if (!SrvSvc.isBindAccepted(bindOutput)) {
            return ShareAttempt(stoppedAt = "the server declined to bind to srvsvc")
        }

        val call = roundTrip(
            socket,
            Smb.smb2PipeTransceiveRequest(
                fileId, SrvSvc.netShareEnumRequest(host), messageId = 6, sessionId, treeId,
            ),
        ) ?: return ShareAttempt(stoppedAt = "NetrShareEnum got no reply")
        val output = Smb.ioctlOutput(call)
            ?: return ShareAttempt(
                stoppedAt = "NetrShareEnum returned nothing (${status(Smb.statusOf(call))})",
            )
        val shares = SrvSvc.parseShares(output)
        if (shares.isEmpty()) {
            return ShareAttempt(
                stoppedAt = "NetrShareEnum answered with no readable entries " +
                    "(${output.size} bytes)",
            )
        }
        return ShareAttempt(shares)
    }

    /** An NTSTATUS by the name an assessor would look up, falling back to the number. */
    private fun status(code: Int?): String = when (code) {
        null -> "no status"
        Smb.STATUS_SUCCESS -> "success"
        Smb.STATUS_ACCESS_DENIED -> "STATUS_ACCESS_DENIED"
        Smb.STATUS_LOGON_FAILURE -> "STATUS_LOGON_FAILURE"
        Smb.STATUS_BAD_NETWORK_NAME -> "STATUS_BAD_NETWORK_NAME"
        Smb.STATUS_NOT_FOUND -> "STATUS_NOT_FOUND"
        else -> "0x%08x".format(code)
    }

    private fun reachable(host: String, port: Int): Boolean = runCatching {
        Socket().use { it.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS) }
        true
    }.getOrDefault(false)

    private fun exchange(host: String, port: Int, request: () -> ByteArray): ByteArray? =
        runCatching {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
                socket.soTimeout = READ_TIMEOUT_MS
                roundTrip(socket, request())
            }
        }.getOrNull()

    /**
     * Sends one request and returns the response that actually carries the answer.
     *
     * A server that cannot answer at once replies STATUS_PENDING and sends the real response on
     * the same connection afterwards. Taking the first message as the answer reads that interim
     * reply as an empty result — which is how a share enumeration that the server was in the
     * middle of satisfying came back as "NetrShareEnum returned nothing (0x00000103)".
     */
    private fun roundTrip(socket: Socket, request: ByteArray): ByteArray? = runCatching {
        socket.getOutputStream().write(request)
        socket.getOutputStream().flush()

        var response = readFramed(socket.getInputStream())
        var waited = 0
        while (response != null && Smb.statusOf(response) == Smb.STATUS_PENDING &&
            waited < MAX_PENDING_REPLIES
        ) {
            response = readFramed(socket.getInputStream())
            waited++
        }
        response
    }.getOrNull()

    /**
     * Reads exactly one NetBIOS-framed message.
     *
     * The length is declared in the header, so this reads it rather than guessing at a buffer
     * size — a short read in the middle of a security blob would silently truncate the NTLM
     * challenge and lose the names it carries.
     */
    private fun readFramed(input: InputStream): ByteArray? {
        val header = ByteArray(4)
        if (!readFully(input, header, 4)) return null
        val length = Smb.framedLength(header) ?: return null
        if (length <= 0 || length > MAX_MESSAGE_BYTES) return null
        val body = ByteArray(length)
        if (!readFully(input, body, length)) return null
        return header + body
    }

    private fun readFully(input: InputStream, into: ByteArray, count: Int): Boolean {
        var read = 0
        while (read < count) {
            val got = input.read(into, read, count - read)
            if (got < 0) return false
            read += got
        }
        return true
    }

    private fun sessionIdOf(response: ByteArray): Long {
        val body = Smb.stripFrame(response) ?: return 0
        if (body.size < Smb.SMB2_HEADER_BYTES) return 0
        return java.nio.ByteBuffer.wrap(body).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong(40)
    }

    // ---- Findings ------------------------------------------------------------------------------

    private fun summary(host: String, assessment: Assessment): Finding {
        val dialect = assessment.negotiated?.dialectName
        return Finding(
            moduleId = id,
            observedAtEpochMs = System.currentTimeMillis(),
            severity = Severity.INFO,
            title = "SMB on $host",
            subject = host,
            detail = buildString {
                append("Answered on ${assessment.port}. ")
                dialect?.let { append("Highest dialect $it. ") }
                assessment.negotiated?.let {
                    append(
                        when {
                            it.signingRequired -> "Signing required. "
                            it.signingEnabled -> "Signing enabled but not required. "
                            else -> "Signing not offered. "
                        },
                    )
                }
                append(if (assessment.smb1Enabled) "SMB1 enabled. " else "SMB1 not offered. ")
                append(if (assessment.nullSession) "Null session accepted." else "Null session refused.")
            },
            data = mapOf(
                "host" to host,
                "port" to assessment.port.toString(),
                "dialect" to dialect.orEmpty(),
                "smb1_enabled" to assessment.smb1Enabled.toString(),
                "signing_required" to (assessment.negotiated?.signingRequired?.toString() ?: ""),
                "signing_enabled" to (assessment.negotiated?.signingEnabled?.toString() ?: ""),
                "null_session" to assessment.nullSession.toString(),
            ),
        )
    }

    private fun smb1Finding(host: String) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.HIGH,
        title = "SMB1 is enabled on $host",
        subject = host,
        detail = "The server negotiated NT LM 0.12. SMB1 is the protocol WannaCry and NotPetya " +
            "spread over; it cannot be signed in any meaningful way, it leaks share and user " +
            "enumeration to unauthenticated callers, and Microsoft has shipped it disabled by " +
            "default for years. Where this is a medical device or an embedded appliance it is " +
            "usually there because the vendor's software still requires it, which makes it a " +
            "segmentation finding rather than a patching one.",
        data = mapOf("host" to host, "smb1_enabled" to "true"),
    )

    private fun signingFinding(host: String, negotiated: Smb.Negotiated) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.HIGH,
        title = "SMB signing is not required on $host",
        subject = host,
        detail = buildString {
            append(
                if (negotiated.signingEnabled) {
                    "Signing is enabled but not required, which means a client that does not ask " +
                        "for it is served anyway. "
                } else {
                    "Signing is not offered at all. "
                },
            )
            append(
                "That is the condition an NTLM relay needs: an authentication captured from any " +
                    "user on this segment — a coerced connection, a poisoned name lookup, a " +
                    "malicious link — can be replayed against this host as that user, without " +
                    "the password ever being known or cracked. Client isolation is not in effect " +
                    "on this segment, so any device here can reach any other to collect one. " +
                    "Dialect ${negotiated.dialectName}.",
            )
        },
        data = mapOf(
            "host" to host,
            "dialect" to negotiated.dialectName,
            "signing_required" to "false",
            "signing_enabled" to negotiated.signingEnabled.toString(),
        ),
    )

    /**
     * What the null session actually reached.
     *
     * This is the finding that turns a configuration note into something an assessor can put in
     * front of an owner: not "anonymous access is permitted" but "anonymous access lists these
     * shares, and these hold files".
     */
    private fun shareFinding(host: String, shares: List<SrvSvc.Share>) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = if (shares.any { it.holdsFiles && !it.isAdministrative }) {
            Severity.CRITICAL
        } else {
            Severity.MEDIUM
        },
        title = "Shares listed without credentials on $host",
        subject = host,
        detail = buildString {
            append("A caller presenting no username and no password enumerated ")
            append("${shares.size} share(s): ")
            append(
                shares.joinToString("; ") { share ->
                    buildString {
                        append(share.name)
                        append(" (${share.kind}")
                        if (share.isAdministrative) append(", administrative")
                        append(")")
                        if (share.remark.isNotBlank()) append(" \"${share.remark}\"")
                    }
                },
            )
            append(". ")
            val files = shares.filter { it.holdsFiles && !it.isAdministrative }
            if (files.isEmpty()) {
                append(
                    "None of these is a file share, so the disclosure is the list itself: it " +
                        "names the machine's role and gives an attacker the share names to aim " +
                        "credentials at.",
                )
            } else {
                append(
                    "${files.joinToString { it.name }} hold files. Whether their contents are " +
                        "readable depends on the permissions on each one, which is the next " +
                        "thing to check by hand — but the names, the layout and the comments " +
                        "are already disclosed to anyone on this segment, and client isolation " +
                        "is not in effect here.",
                )
            }
        },
        data = mapOf(
            "host" to host,
            "share_count" to shares.size.toString(),
            "shares" to shares.joinToString { it.name },
            "file_shares" to shares.filter { it.holdsFiles && !it.isAdministrative }
                .joinToString { it.name },
        ).filterValues { it.isNotBlank() },
    )

    /**
     * Why the share list is absent.
     *
     * Without this, a server that refused the enumeration and a server with nothing shared
     * produce the same report — and only one of those is the configuration holding.
     */
    private fun shareLookupFinding(host: String, stoppedAt: String?) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.INFO,
        title = "Null session could not list shares on $host",
        subject = host,
        detail = "The anonymous session was granted, but enumerating shares over srvsvc did not " +
            "complete: " + (stoppedAt ?: "no reason was recorded") + ". The session itself is " +
            "still the finding above; this says the server did not go on to hand over its share " +
            "list, which is the restriction working. Listing shares by name over SMB1 — which " +
            "this host still speaks — is the next thing to try by hand.",
        data = mapOf("host" to host, "stopped_at" to stoppedAt.orEmpty())
            .filterValues { it.isNotBlank() },
    )

    private fun nullSessionFinding(host: String, challenge: Ntlm.Challenge?) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.HIGH,
        title = "Null session accepted on $host",
        subject = host,
        detail = "The server completed a session setup for a caller presenting no username and " +
            "no password. What that session can then reach depends on the share and registry " +
            "permissions, but on a file server it commonly includes the share list, and on " +
            "older configurations the local user and group list as well — which is the input to " +
            "a password attack against every other service on the estate. " +
            challenge?.describe().orEmpty(),
        data = mapOf("host" to host, "null_session" to "true"),
    )

    private fun disclosureFinding(host: String, challenge: Ntlm.Challenge) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = if (challenge.isDomainJoined) Severity.MEDIUM else Severity.LOW,
        title = "SMB discloses its identity before authentication — $host",
        subject = host,
        detail = buildString {
            append(challenge.describe())
            append(" All of this came back from a session setup that presented no credentials. ")
            if (challenge.isDomainJoined) {
                append(
                    "The DNS domain name is the useful part: it names the directory this machine " +
                        "trusts, which is where an account attack would be aimed, and confirms " +
                        "that whatever else is on this segment is reaching a domain controller " +
                        "from here.",
                )
            } else {
                append(
                    "The names and OS build narrow down what this device is and which published " +
                        "vulnerabilities apply to it.",
                )
            }
        },
        // Blank entries are dropped rather than printed as empty keys: a field the server did
        // not send is not a field worth a line in the report.
        data = mapOf(
            "host" to host,
            "netbios_name" to challenge.netbiosComputer.orEmpty(),
            "netbios_domain" to challenge.netbiosDomain.orEmpty(),
            "dns_computer" to challenge.dnsComputer.orEmpty(),
            "dns_domain" to challenge.dnsDomain.orEmpty(),
            "dns_forest" to challenge.dnsForest.orEmpty(),
            "os_version" to challenge.osVersion.orEmpty(),
            "os_version_is_claim" to challenge.osVersionIsCompatibilityClaim.toString(),
            "domain_joined" to challenge.isDomainJoined.toString(),
        ).filterValues { it.isNotBlank() },
    )

    private companion object {
        val SMB_PORTS = listOf(445, 139)
        const val CONNECT_TIMEOUT_MS = 3_000

        /**
         * How many interim replies to read through. A server sends one STATUS_PENDING and then
         * the answer; more than a couple means something else is wrong and waiting longer will
         * not fix it.
         */
        const val MAX_PENDING_REPLIES = 4
        const val READ_TIMEOUT_MS = 5_000

        /** A negotiate or session setup is a few hundred bytes; anything vast is not one. */
        const val MAX_MESSAGE_BYTES = 256 * 1024
    }
}
