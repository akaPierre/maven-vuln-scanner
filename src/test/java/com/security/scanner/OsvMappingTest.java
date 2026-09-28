package com.security.scanner;

import com.google.gson.Gson;
import com.security.model.Dependency;
import com.security.model.Severity;
import com.security.model.Vulnerability;
import com.security.model.osv.OsvVulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Mapping of OSV records to scanner results, without any HTTP involved. */
class OsvMappingTest {

    // Trimmed copy of the real OSV record for Log4Shell
    private static final String LOG4SHELL = """
            {
              "id": "GHSA-jfh8-c2jp-5v3q",
              "summary": "Remote code injection in Log4j",
              "aliases": ["CVE-2021-44228"],
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
              "affected": [
                {
                  "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]}]
                },
                {
                  "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.3.1"}]}]
                },
                {
                  "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.4"}, {"fixed": "2.12.2"}]}]
                },
                {
                  "package": {"ecosystem": "Maven", "name": "org.ops4j.pax.logging:pax-logging-log4j2"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.8.0"}, {"fixed": "1.9.2"}]}]
                }
              ],
              "database_specific": {"severity": "CRITICAL"}
            }
            """;

    @Test
    void mapsRealAdvisory() {
        OsvVulnerability osv = new Gson().fromJson(LOG4SHELL, OsvVulnerability.class);
        Dependency dep = new Dependency("org.apache.logging.log4j", "log4j-core", "2.14.1", "compile");

        Vulnerability v = OsvClient.toVulnerability(dep, osv);

        assertEquals("CVE-2021-44228", v.displayId());
        assertEquals(Severity.CRITICAL, v.severity());
        assertEquals(10.0, v.cvssScore());
        assertEquals(List.of("2.15.0"), v.fixedVersions(), "only upgrades for this package, not older branches");
    }

    @Test
    void unknownSeverityWhenAdvisoryHasNoRating() {
        OsvVulnerability osv = new Gson().fromJson("{\"id\":\"OSV-1\"}", OsvVulnerability.class);

        Vulnerability v = OsvClient.toVulnerability(new Dependency("g", "a", "1.0", "compile"), osv);

        assertEquals(Severity.UNKNOWN, v.severity());
        assertEquals("No description available", v.title());
        assertTrue(v.aliases().isEmpty());
        assertTrue(v.fixedVersions().isEmpty());
    }

    @Test
    void comparesMavenStyleVersions() {
        assertTrue(OsvClient.compareVersions("2.15.0", "2.14.1") > 0);
        assertTrue(OsvClient.compareVersions("2.12.2", "2.14.1") < 0);
        assertTrue(OsvClient.compareVersions("2.10", "2.9.8") > 0);
        assertTrue(OsvClient.compareVersions("4.1.101.Final", "4.1.100.Final") > 0);
        assertTrue(OsvClient.compareVersions("1.0", "1.0-beta") > 0);
        assertEquals(0, OsvClient.compareVersions("1.0", "1.0.0"));
    }
}
