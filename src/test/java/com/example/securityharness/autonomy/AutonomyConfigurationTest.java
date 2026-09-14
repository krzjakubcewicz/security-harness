package com.example.securityharness.autonomy;

import com.example.securityharness.config.ConfigLoader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AutonomyConfigurationTest {

    @Test
    void loadsGatesInTheOrderTheyAreWritten(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("autonomy.yaml");
        Files.writeString(file, """
                gates:
                  - name: escalate-major-version-changes
                    match:
                      versionChange: major
                    action: jira
                  - name: auto-merge-green-dependency-bumps
                    match:
                      versionChange: [minor, patch]
                      changeKind: dependency_file_only
                      buildGate: allow
                    action: auto_merge
                """);

        List<AutonomyRule> gates = ConfigLoader.yaml()
                .load(file, AutonomyConfiguration.class).gates();

        assertEquals(2, gates.size());
        assertEquals("escalate-major-version-changes", gates.get(0).name());
        assertEquals(Map.of("versionChange", "major"), gates.get(0).match());
        assertEquals(AutonomyAction.JIRA, gates.get(0).action());
        assertEquals(AutonomyAction.AUTO_MERGE, gates.get(1).action());
        assertEquals(List.of("minor", "patch"), gates.get(1).match().get("versionChange"));
        assertEquals("dependency_file_only", gates.get(1).match().get("changeKind"));
    }

    @Test
    void aRuleWithNoActionIsRejectedByName(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("autonomy.yaml");
        Files.writeString(file, """
                gates:
                  - name: half-written
                    match:
                      versionChange: major
                """);

        Exception thrown = assertThrows(Exception.class,
                () -> ConfigLoader.yaml().load(file, AutonomyConfiguration.class));

        assertTrue(thrown.getMessage().contains("half-written")
                        || thrown.getCause().getMessage().contains("half-written"),
                "the failure should name the rule: " + thrown);
    }

    @Test
    void aRuleWithNoMatchMatchesEverything(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("autonomy.yaml");
        Files.writeString(file, """
                gates:
                  - name: catch-all
                    action: pull_request
                """);

        AutonomyRule rule = ConfigLoader.yaml()
                .load(file, AutonomyConfiguration.class).gates().get(0);

        assertEquals(Map.of(), rule.match());
    }
}
