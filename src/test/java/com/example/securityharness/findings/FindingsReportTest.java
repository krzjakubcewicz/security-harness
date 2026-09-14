package com.example.securityharness.findings;

import com.example.securityharness.config.ConfigLoadException;
import com.example.securityharness.config.ConfigLoader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingsReportTest {

    @Test
    void loadsValidFindings(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("findings.json");
        Files.writeString(file, """
                {
                  "generated": "2026-08-03T02:14:07Z",
                  "scanner": "internal-composition-scan",
                  "findings": [
                    {
                      "id": "F-40218",
                      "cve": "CVE-2022-1471",
                      "severity": "critical",
                      "service": "inventory-api",
                      "package": "org.yaml:snakeyaml",
                      "installed_version": "1.30",
                      "path": "transitive via org.springframework.boot:spring-boot-starter",
                      "fixed_version": "2.0",
                      "sla_days_remaining": 4,
                      "notes": "Constructor deserialization. Reachability not assessed."
                    },
                    {
                      "id": "F-40220",
                      "cve": "CVE-2015-6420",
                      "severity": "high",
                      "service": "inventory-api",
                      "package": "commons-collections:commons-collections",
                      "installed_version": "3.2.1",
                      "path": "direct",
                      "fixed_version": null,
                      "sla_days_remaining": -63,
                      "notes": "No patched release on the 3.x line. Successor artifact is commons-collections4, different package namespace."
                    }
                  ]
                }
                """);

        List<Finding> findings = ConfigLoader.json().load(file, FindingsReport.class).findings();

        assertEquals(2, findings.size());

        Finding first = findings.get(0);
        assertEquals("F-40218", first.id());
        assertEquals("CVE-2022-1471", first.cve());
        assertEquals(Severity.CRITICAL, first.severity());
        assertEquals("inventory-api", first.service());
        assertEquals("org.yaml:snakeyaml", first.packageName());
        assertEquals("1.30", first.installedVersion());
        assertEquals("transitive via org.springframework.boot:spring-boot-starter", first.path());
        assertEquals("2.0", first.fixedVersion());
        assertEquals(4, first.slaDaysRemaining());
        assertEquals("Constructor deserialization. Reachability not assessed.", first.notes());

        Finding second = findings.get(1);
        assertEquals(Severity.HIGH, second.severity());
        assertNull(second.fixedVersion());
        assertEquals(-63, second.slaDaysRemaining());
    }

    @Test
    void missingFileThrowsLoadException(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("does-not-exist.json");

        ConfigLoadException ex = assertThrows(ConfigLoadException.class,
                () -> ConfigLoader.json().load(missing, FindingsReport.class));

        assertTrue(ex.getMessage().toLowerCase().contains("not found")
                || ex.getMessage().toLowerCase().contains("no such file"));
    }

    @Test
    void malformedJsonThrowsLoadException(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("findings.json");
        Files.writeString(file, "{ this is not valid json ");

        assertThrows(ConfigLoadException.class, () -> ConfigLoader.json().load(file, FindingsReport.class));
    }

    @Test
    void unrecognizedSeverityThrowsLoadException(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("findings.json");
        Files.writeString(file, """
                {
                  "generated": "2026-08-03T02:14:07Z",
                  "scanner": "internal-composition-scan",
                  "findings": [
                    {
                      "id": "F-1",
                      "cve": "CVE-0000-0000",
                      "severity": "extreme",
                      "service": "inventory-api",
                      "package": "example:example",
                      "installed_version": "1.0",
                      "path": "direct",
                      "fixed_version": "1.1",
                      "sla_days_remaining": 1,
                      "notes": "n/a"
                    }
                  ]
                }
                """);

        assertThrows(ConfigLoadException.class, () -> ConfigLoader.json().load(file, FindingsReport.class));
    }

    @Test
    void severityMatchIsCaseInsensitive(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("findings.json");
        Files.writeString(file, """
                {
                  "generated": "2026-08-03T02:14:07Z",
                  "scanner": "internal-composition-scan",
                  "findings": [
                    {
                      "id": "F-1",
                      "cve": "CVE-0000-0000",
                      "severity": "HiGh",
                      "service": "inventory-api",
                      "package": "example:example",
                      "installed_version": "1.0",
                      "path": "direct",
                      "fixed_version": "1.1",
                      "sla_days_remaining": 1,
                      "notes": "n/a"
                    }
                  ]
                }
                """);

        List<Finding> findings = ConfigLoader.json().load(file, FindingsReport.class).findings();

        assertEquals(Severity.HIGH, findings.getFirst().severity());
    }
}
