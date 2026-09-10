package dev.cyphernova.mobileops.core.capture

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import dev.cyphernova.mobileops.MainActivity
import dev.cyphernova.mobileops.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Captures every packet this device sends and receives, with no root at all.
 *
 * The trick is that [VpnService] hands any app a TUN interface and the system route table
 * pointed at it. We are not tunnelling anywhere — we read each packet, write it to a pcap, and
 * forward it on ourselves through protected sockets. That makes this the one capture path on a
 * stock Android device that sees real application traffic, which is why it is worth the
 * userspace TCP implementation behind it.
 *
 * What it sees: this device's own traffic, in full, including inside TLS-terminating apps at the
 * IP layer. What it does not see: other stations' traffic — that needs monitor mode.
 */
class CaptureVpnService : VpnService() {

    private var tunnel: ParcelFileDescriptor? = null
    private var scope: CoroutineScope? = null
    private var writer: PcapWriter? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                teardown()
                return START_NOT_STICKY
            }
            else -> start()
        }
        return START_STICKY
    }

    private fun start() {
        if (tunnel != null) return

        val descriptor = establishTunnel()
        if (descriptor == null) {
            CaptureController.stopped("Could not establish the TUN interface.")
            stopSelf()
            return
        }
        tunnel = descriptor

        val directory = File(filesDir, "captures").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val pcap = File(directory, "capture-$stamp.pcap")
        val pcapWriter = PcapWriter(pcap)
        writer = pcapWriter

        startForeground(NOTIFICATION_ID, buildNotification(pcap.name))
        CaptureController.started(pcap.absolutePath)

        val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        scope = serviceScope
        serviceScope.launch { pump(descriptor, pcapWriter, serviceScope) }
    }

    private fun establishTunnel(): ParcelFileDescriptor? = runCatching {
        Builder()
            .setSession(SESSION)
            .addAddress(TUN_ADDRESS, TUN_PREFIX)
            // Default route: everything the device sends arrives here to be captured.
            .addRoute("0.0.0.0", 0)
            .addDnsServer(DNS_PRIMARY)
            .addDnsServer(DNS_SECONDARY)
            .setMtu(MTU)
            .also { builder ->
                // Our own relay sockets must not re-enter the tunnel, or every forwarded packet
                // would loop straight back into us.
                runCatching { builder.addDisallowedApplication(packageName) }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    builder.setMetered(false)
                }
            }
            .establish()
    }.getOrNull()

    private suspend fun pump(
        descriptor: ParcelFileDescriptor,
        pcapWriter: PcapWriter,
        serviceScope: CoroutineScope,
    ) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val output = FileOutputStream(descriptor.fileDescriptor)

        // Everything heading back to the device goes through here, so it is also the one place
        // that records the inbound half of the capture.
        val emit: (ByteArray) -> Unit = { packet ->
            synchronized(output) {
                runCatching {
                    output.write(packet)
                    pcapWriter.write(packet)
                }
            }
        }

        val tcpRelay = TcpRelay(serviceScope, ::protect, emit)
        val udpRelay = UdpRelay(serviceScope, ::protect, emit)

        // Status ticker: keeps the UI's counters live and reaps idle UDP flows.
        serviceScope.launch {
            while (isActive) {
                udpRelay.evictIdle()
                CaptureController.update(
                    packets = pcapWriter.packetCount,
                    bytes = pcapWriter.byteCount,
                    tcpFlows = tcpRelay.activeFlows,
                    udpFlows = udpRelay.activeFlows,
                )
                delay(STATUS_INTERVAL_MS)
            }
        }

        val buffer = ByteArray(MTU)
        try {
            while (serviceScope.isActive) {
                val read = input.read(buffer)
                if (read <= 0) {
                    if (read < 0) break
                    continue
                }

                pcapWriter.write(buffer.copyOf(read), read)

                val packet = Packets.parseIp4(buffer, read) ?: continue
                when (packet.protocol) {
                    PROTO_TCP -> Packets.parseTcp(packet)?.let { tcpRelay.handle(packet, it) }
                    PROTO_UDP -> Packets.parseUdp(packet)?.let { udpRelay.handle(packet, it) }
                    // ICMP and everything else is captured but not forwarded: relaying it needs
                    // a raw socket, which is Tier 1.
                    else -> Unit
                }
            }
        } catch (_: Exception) {
            // Read fails when the descriptor closes during teardown; that is the normal exit.
        } finally {
            tcpRelay.closeAll()
            udpRelay.closeAll()
            runCatching { input.close() }
            runCatching { output.close() }
        }
    }

    private fun buildNotification(fileName: String): Notification {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Packet capture", NotificationManager.IMPORTANCE_LOW)
                    .apply { description = "Shown while MobileOps is capturing traffic." },
            )
        }

        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("Capturing traffic")
            .setContentText("Writing $fileName")
            .setSmallIcon(R.drawable.ic_capture)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    private fun teardown() {
        scope?.cancel()
        scope = null
        writer?.close()
        writer = null
        runCatching { tunnel?.close() }
        tunnel = null
        CaptureController.stopped()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        // The user revoked the VPN from system settings, or another VPN took over.
        teardown()
        super.onRevoke()
    }

    override fun onDestroy() {
        teardown()
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "dev.cyphernova.mobileops.STOP_CAPTURE"

        private const val SESSION = "MobileOps capture"
        private const val TUN_ADDRESS = "10.28.14.2"
        private const val TUN_PREFIX = 32
        private const val DNS_PRIMARY = "1.1.1.1"
        private const val DNS_SECONDARY = "8.8.8.8"
        private const val MTU = 1500
        private const val CHANNEL_ID = "capture"
        private const val NOTIFICATION_ID = 0x4D4F
        private const val STATUS_INTERVAL_MS = 1_000L

        fun start(context: Context) {
            context.startService(Intent(context, CaptureVpnService::class.java))
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, CaptureVpnService::class.java).setAction(ACTION_STOP),
            )
        }
    }
}
