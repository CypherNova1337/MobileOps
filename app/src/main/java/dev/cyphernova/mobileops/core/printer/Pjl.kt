package dev.cyphernova.mobileops.core.printer

/**
 * PJL, the control language almost every network printer speaks on port 9100.
 *
 * Port 9100 is a raw job socket with no authentication of any kind — whatever arrives is
 * interpreted, and PJL commands are interpreted alongside the print data. That is the design, not
 * a defect in one product, which is why a printer reachable from a user segment is a finding
 * rather than a footnote.
 *
 * **Everything here is read-only.** PJL can also set the display message, change defaults, write
 * and delete files on the printer's storage, and lock the control panel. None of that is
 * generated here: an assessment has no business modifying a device it was asked to look at, and a
 * changed default on a shared printer is an outage someone else has to diagnose.
 */
object Pjl {

    /** The Universal Exit Language sequence, which puts the printer into PJL. */
    const val UEL = "\u001B%-12345X"

    private const val FORM_FEED = '\u000C'

    /**
     * The queries worth asking, in one job.
     *
     * They are sent together because each one costs a round trip on a device that is often slow
     * to answer, and because opening 9100 repeatedly on a busy printer is more disruptive than
     * opening it once.
     */
    fun inventoryRequest(fileEntries: Int = 50): ByteArray = buildString {
        append(UEL)
        append("@PJL INFO ID\r\n")
        append("@PJL INFO CONFIG\r\n")
        append("@PJL INFO VARIABLES\r\n")
        append("@PJL INFO STATUS\r\n")
        // A directory listing of the printer's own storage. Stored jobs, fonts and saved scans
        // live here, and on many models it is readable without any credential at all.
        append("@PJL FSDIRLIST NAME=\"0:\\\" ENTRY=1 COUNT=$fileEntries\r\n")
        append(UEL)
    }.toByteArray(Charsets.US_ASCII)

    /** One answered query. */
    data class Block(val command: String, val lines: List<String>)

    /**
     * Splits a reply into the blocks the printer answered.
     *
     * A printer echoes the command it is answering and terminates each block with a form feed,
     * but not every model answers every query and the order is not guaranteed, so the reply is
     * parsed by what came back rather than by what was asked.
     */
    fun parse(reply: String): List<Block> {
        if (reply.isBlank()) return emptyList()
        return reply.split(FORM_FEED)
            .mapNotNull { chunk ->
                val lines = chunk.replace(UEL, "")
                    .lines()
                    .map { it.trim() }
                    .filter { it.isNotBlank() }
                val header = lines.firstOrNull { it.startsWith("@PJL", ignoreCase = true) }
                    ?: return@mapNotNull null
                val command = header.removePrefix("@PJL").trim()
                Block(command, lines.drop(lines.indexOf(header) + 1))
            }
            .filter { it.lines.isNotEmpty() }
    }

    /** The model string from `INFO ID`, unquoted. */
    fun modelIn(blocks: List<Block>): String? = blocks
        .firstOrNull { it.command.startsWith("INFO ID", ignoreCase = true) }
        ?.lines?.firstOrNull()
        ?.trim('"', ' ')
        ?.takeIf { it.isNotBlank() }

    /** Everything `INFO VARIABLES` and `INFO CONFIG` reported, as name to value. */
    fun settingsIn(blocks: List<Block>): Map<String, String> = blocks
        .filter {
            it.command.startsWith("INFO VARIABLES", ignoreCase = true) ||
                it.command.startsWith("INFO CONFIG", ignoreCase = true)
        }
        .flatMap { block ->
            block.lines.mapNotNull { line ->
                // Variables arrive as NAME=VALUE with the permitted range after it on the same
                // line; config arrives as indented NAME=VALUE under a section heading.
                val name = line.substringBefore('=', "").trim()
                if (name.isBlank() || !line.contains('=')) return@mapNotNull null
                val value = line.substringAfter('=').trim().substringBefore(" [")
                name to value
            }
        }
        .toMap()

    /** One entry from a filesystem listing. */
    data class Entry(val name: String, val sizeBytes: Long?, val isDirectory: Boolean)

    /**
     * The storage listing from `FSDIRLIST`.
     *
     * Entries arrive as `NAME TYPE SIZE`, where TYPE is `TYPE=FILE` or `TYPE=DIR`. A model that
     * refuses the command answers with `FILEERROR`, which is not a listing and not an error worth
     * reporting — it is the device declining, which is the correct behaviour.
     */
    fun filesIn(blocks: List<Block>): List<Entry> = blocks
        .filter { it.command.startsWith("FSDIRLIST", ignoreCase = true) }
        .flatMap { it.lines }
        .filterNot { it.contains("FILEERROR", ignoreCase = true) }
        .mapNotNull { line ->
            val parts = line.split(Regex("\\s+")).filter { it.isNotBlank() }
            if (parts.size < 2) return@mapNotNull null
            val name = parts.first()
            if (name == "." || name == "..") return@mapNotNull null
            val type = parts.firstOrNull { it.startsWith("TYPE=", ignoreCase = true) }
                ?.substringAfter('=').orEmpty()
            val size = parts.firstOrNull { it.startsWith("SIZE=", ignoreCase = true) }
                ?.substringAfter('=')?.toLongOrNull()
                ?: parts.getOrNull(1)?.toLongOrNull()
            Entry(name, size, type.equals("DIR", ignoreCase = true))
        }

    /** What a setting means for the assessment, rather than for whoever is printing. */
    enum class Concern {
        /** No PJL password, so the device takes configuration changes from anyone. */
        NO_PJL_PASSWORD,

        /** Stored jobs and scans sit on storage that is not locked or encrypted. */
        STORAGE_UNPROTECTED,

        /** The device is configured to authenticate to something else on the network. */
        REACHES_SERVER,
    }

    /** One setting worth reporting, with what its value actually means. */
    data class Note(
        val key: String,
        val value: String,
        val concern: Concern,
        val meaning: String,
    )

    /**
     * The settings that change what an assessor should do next.
     *
     * A keyword match alone is not enough, and reporting one is how a printer with `PASSWORD=
     * DISABLED` gets written up under a paragraph about stored scan-to-folder credentials it does
     * not have. What matters is the value: a mail server name means the device holds an account
     * somewhere else, while a password feature switched off means the device itself is open.
     */
    fun concerns(settings: Map<String, String>): List<Note> = settings.mapNotNull { (key, raw) ->
        val value = raw.trim().trim('"')
        val off = value.isBlank() || value.uppercase() in OFF_VALUES

        when {
            key.contains("PASSWORD", ignoreCase = true) && off -> Note(
                key, value, Concern.NO_PJL_PASSWORD,
                "no PJL password is set, so any device on this segment can change this " +
                    "printer's defaults and panel message, not merely read them",
            )

            (key.contains("DISKLOCK", ignoreCase = true) ||
                key.contains("ENCRYPT", ignoreCase = true)) && off -> Note(
                key, value, Concern.STORAGE_UNPROTECTED,
                "the printer's storage is not protected, so held jobs and scans on it survive " +
                    "in readable form",
            )

            // A server name is only a finding when there is a name. The same key set to nothing
            // is the feature being unconfigured, which is the opposite of a finding.
            SERVER_KEYS.any { key.contains(it, ignoreCase = true) } && !off && looksLikeHost(value) ->
                Note(
                    key, value, Concern.REACHES_SERVER,
                    "the printer authenticates to '$value', so it stores an account for that " +
                        "system in a form it can replay — and that account is usually on the " +
                        "file server or the mail system rather than on the printer",
                )

            else -> null
        }
    }

    private fun looksLikeHost(value: String): Boolean =
        value.length > 1 && (value.contains('.') || value.contains(':') || value.contains('\\'))

    private val OFF_VALUES = setOf("DISABLED", "OFF", "NONE", "NO", "0", "FALSE", "UNSET")

    private val SERVER_KEYS = listOf("SMTP", "LDAP", "KERBEROS", "DOMAIN", "MAILSERVER", "SMB")
}
