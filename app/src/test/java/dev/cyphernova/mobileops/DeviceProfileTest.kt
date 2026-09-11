package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.identity.DeviceProfiles
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class DeviceProfileTest {

    private val macPattern = Regex("^([0-9A-F]{2}:){5}[0-9A-F]{2}$")

    @Test
    fun `vendor profiles keep their oui and randomise the tail`() {
        val profile = DeviceProfiles.byId("win11-laptop")
        val macs = (1..20).map { profile.generateMac(Random(it)) }

        macs.forEach { mac ->
            assertTrue("well formed: $mac", macPattern.matches(mac))
            assertTrue("keeps OUI: $mac", mac.startsWith(profile.vendorOui))
        }
        assertTrue("tail varies", macs.distinct().size > 1)
    }

    @Test
    fun `anonymous profile sets the locally administered bit and clears multicast`() {
        val profile = DeviceProfiles.byId("anonymous")
        (1..50).forEach { seed ->
            val mac = profile.generateMac(Random(seed))
            assertTrue("well formed: $mac", macPattern.matches(mac))

            val first = mac.substringBefore(':').toInt(16)
            // Bit 1 set marks the address as locally administered; bit 0 clear keeps it unicast.
            assertEquals("locally administered: $mac", 0x02, first and 0x02)
            assertEquals("unicast: $mac", 0x00, first and 0x01)
        }
    }

    @Test
    fun `every builtin profile generates a valid mac`() {
        DeviceProfiles.builtIn.forEach { profile ->
            val mac = profile.generateMac(Random(7))
            assertTrue("${profile.id}: $mac", macPattern.matches(mac))
        }
    }

    @Test
    fun `hostnames carry the profile prefix and vary`() {
        val profile = DeviceProfiles.byId("win11-laptop")
        val names = (1..10).map { profile.generateHostname(Random(it)) }
        names.forEach { assertTrue(it.startsWith("DESKTOP-")) }
        assertTrue(names.distinct().size > 1)
    }

    @Test
    fun `windows profile carries the ttl that actually distinguishes it`() {
        // TTL 128 vs 64 is the single strongest passive OS signal; if this regresses the whole
        // profile stops being convincing to a fingerprinter.
        assertEquals(128, DeviceProfiles.byId("win11-laptop").initialTtl)
        assertEquals(64, DeviceProfiles.byId("macbook").initialTtl)
        assertNotEquals(
            DeviceProfiles.byId("win11-laptop").initialTtl,
            DeviceProfiles.byId("linux-workstation").initialTtl,
        )
    }

    @Test
    fun `unknown id falls back to passthrough rather than throwing`() {
        assertEquals(DeviceProfiles.PASSTHROUGH, DeviceProfiles.byId("nonsense"))
    }
}
