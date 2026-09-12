package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.segment.ReachedAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * From a live run, and from the operator confirming what the hardware actually is: three
 * addresses answered outside the local segment and the report counted all three as the estate's
 * segmentation failing. Only one of them might be.
 */
class ReachedAddressTest {

    @Test
    fun `the cable modem is upstream equipment, not another segment`() {
        assertEquals(
            ReachedAddress.Kind.UPSTREAM_EQUIPMENT,
            ReachedAddress.classify("192.168.100.1", 80),
        )
        // Standard on every vendor's DOCSIS hardware, so the port it answers on is irrelevant.
        assertEquals(
            ReachedAddress.Kind.UPSTREAM_EQUIPMENT,
            ReachedAddress.classify("192.168.100.1", null),
        )
    }

    /**
     * A router replies to ICMP for every address it holds, from any interface. A ping answered by
     * a gateway address is as easily the router talking about itself as proof of a routed path.
     */
    @Test
    fun `a gateway address answering only icmp is not proof of a routed path`() {
        assertEquals(ReachedAddress.Kind.GATEWAY_ECHO, ReachedAddress.classify("192.168.10.1", null))
        assertEquals(ReachedAddress.Kind.GATEWAY_ECHO, ReachedAddress.classify("192.168.20.1", null))
    }

    @Test
    fun `a service answering is a routed path whatever the address`() {
        assertEquals(ReachedAddress.Kind.ROUTED_SERVICE, ReachedAddress.classify("192.168.10.1", 80))
        assertEquals(ReachedAddress.Kind.ROUTED_SERVICE, ReachedAddress.classify("10.20.30.40", 443))
    }

    /** A host inside the range that is not the gateway really is that range being reached. */
    @Test
    fun `an ordinary host answering icmp is a routed path`() {
        assertEquals(
            ReachedAddress.Kind.ROUTED_SERVICE,
            ReachedAddress.classify("192.168.10.57", null),
        )
    }

    @Test
    fun `every kind explains itself`() {
        ReachedAddress.Kind.entries.forEach {
            assertTrue(it.name, ReachedAddress.explain(it).isNotBlank())
        }
    }
}
