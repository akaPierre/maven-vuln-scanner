package com.security.scanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CvssV3Test {

    // Expected scores from the FIRST CVSS v3.1 calculator
    @ParameterizedTest
    @CsvSource({
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H, 9.8",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H, 10.0",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N, 6.1",
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N, 5.5",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H, 8.1",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H, 7.5",
            "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, 8.8",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 0.0",
    })
    void computesBaseScore(String vector, double expected) {
        assertEquals(expected, CvssV3.baseScore(vector).orElseThrow(), 0.0001);
    }

    @Test
    void rejectsUnsupportedOrInvalidVectors() {
        assertTrue(CvssV3.baseScore(null).isEmpty());
        assertTrue(CvssV3.baseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").isEmpty());
        assertTrue(CvssV3.baseScore("CVSS:3.1/AV:N/AC:L").isEmpty());
        assertTrue(CvssV3.baseScore("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").isEmpty());
    }
}
