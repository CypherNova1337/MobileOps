package dev.cyphernova.mobileops.modules.tier1

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

data class ShellResult(val exitCode: Int, val stdout: String, val timedOut: Boolean = false) {
    val ok: Boolean get() = exitCode == 0 && !timedOut
}

/** Runs commands through `su`. Every call is bounded so a hung binary cannot wedge a module. */
object RootShell {

    suspend fun exec(command: String, timeoutMs: Long = 15_000): ShellResult =
        withContext(Dispatchers.IO) {
            withTimeoutOrNull(timeoutMs) {
                runCatching {
                    val process = ProcessBuilder("su", "-c", command)
                        .redirectErrorStream(true)
                        .start()
                    val output = process.inputStream.bufferedReader().use { it.readText() }
                    ShellResult(process.waitFor(), output.trim())
                }.getOrElse { ShellResult(-1, it.message.orEmpty()) }
            } ?: ShellResult(-1, "timed out after ${timeoutMs}ms", timedOut = true)
        }

    /** Locates a binary on the root PATH, including the usual Magisk/BusyBox drop points. */
    suspend fun which(binary: String): String? {
        val result = exec("which $binary || ls /data/local/tmp/$binary 2>/dev/null", timeoutMs = 5_000)
        return result.stdout.lineSequence().firstOrNull { it.startsWith("/") }?.trim()
    }
}
