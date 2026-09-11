package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.exploit.PathEvidence
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PathEvidenceTest {

    /**
     * The regression. A control request that simply timed out used to leave the baseline null,
     * and the filter was written to skip itself in that case — so one lost packet turned the
     * safeguard off and every probed path was reported as exposed. Absence of a control is a
     * reason to say nothing, not a reason to say everything.
     */
    @Test
    fun `no completed control means no path probing`() {
        assertFalse(PathEvidence.canProbePaths(0))
        assertTrue(PathEvidence.canProbePaths(1))
        assertTrue(PathEvidence.canProbePaths(2))
    }

    /**
     * Taken from a live run against a Netgear RAX42: /server-status, /admin, /cgi-bin/ and
     * /setup.cgi all returned 200 with an identical 2489 bytes, and none of them loaded in a
     * browser. They are one page under four names.
     */
    @Test
    fun `a response the size of a known decoy is not a finding`() {
        val decoys = setOf(2489)
        assertFalse(PathEvidence.isDistinct(2489, decoys))
        assertTrue(PathEvidence.isDistinct(1024, decoys))
    }

    /** The root counts as a decoy: a single-page interface serves its shell for everything. */
    @Test
    fun `the root page is one of the decoys`() {
        val decoys = setOf(2489, 15320)
        assertFalse(PathEvidence.isDistinct(15320, decoys))
        assertTrue(PathEvidence.isDistinct(15321, decoys))
    }

    @Test
    fun `an empty body is never a finding`() {
        assertFalse(PathEvidence.isDistinct(0, emptySet()))
        assertFalse(PathEvidence.isDistinct(0, setOf(2489)))
    }

    @Test
    fun `with no decoys at all a real body still stands`() {
        assertTrue(PathEvidence.isDistinct(2489, emptySet()))
    }
}
