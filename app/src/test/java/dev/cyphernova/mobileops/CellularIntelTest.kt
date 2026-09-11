package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.radio.CellularIntel
import dev.cyphernova.mobileops.core.radio.CellularIntel.Generation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CellularIntelTest {

    @Test
    fun `known operators resolve from mcc and mnc`() {
        assertEquals("T-Mobile", CellularIntel.operatorOf("310", "260"))
        assertEquals("AT&T", CellularIntel.operatorOf("310", "410"))
        assertEquals("EE", CellularIntel.operatorOf("234", "30"))
    }

    /** The leading zero in an MNC is significant, so both widths have to resolve. */
    @Test
    fun `a two-digit mnc resolves whether or not it is zero-padded`() {
        assertEquals("Verizon", CellularIntel.operatorOf("310", "004"))
        assertEquals("O2 UK", CellularIntel.operatorOf("234", "10"))
    }

    @Test
    fun `an unlisted operator is reported by number rather than guessed`() {
        assertNull(CellularIntel.operatorOf("999", "99"))
        assertTrue(CellularIntel.describeOperator("999", "99").contains("999"))
        assertEquals("operator unidentified", CellularIntel.describeOperator(null, null))
    }

    /**
     * LTE and NR report RSRP, which sits about 20 dB below the RSSI the older generations
     * report, so one scale applied to both would call every LTE cell weak.
     */
    @Test
    fun `signal quality is scaled per generation`() {
        assertEquals("excellent", CellularIntel.quality(-75, Generation.LTE))
        assertEquals("good", CellularIntel.quality(-75, Generation.GSM))
        assertEquals("barely present", CellularIntel.quality(-120, Generation.NR))
    }

    @Test
    fun `a missing reading is not reported as a measurement`() {
        assertEquals("no reading", CellularIntel.quality(0, Generation.LTE))
        assertEquals("no reading", CellularIntel.quality(Int.MAX_VALUE, Generation.LTE))
    }

    @Test
    fun `a live 2g carrier is called out as the downgrade risk`() {
        val exposure = CellularIntel.downgradeExposure(setOf(Generation.LTE, Generation.GSM))
        assertNotNull(exposure)
        assertTrue(exposure!!.contains("2G"))
    }

    @Test
    fun `3g alone is a lesser note and a modern-only environment is clean`() {
        assertTrue(CellularIntel.downgradeExposure(setOf(Generation.WCDMA))!!.contains("3G"))
        assertNull(CellularIntel.downgradeExposure(setOf(Generation.LTE, Generation.NR)))
        assertNull(CellularIntel.downgradeExposure(emptySet()))
    }
}
