package com.example.securityharness.guards;

import com.example.securityharness.agent.ToolCall;
import com.example.securityharness.config.ConfigLoadException;
import com.example.securityharness.config.ConfigLoader;
import com.example.securityharness.findings.Finding;
import com.example.securityharness.findings.Severity;
import com.example.securityharness.policy.Verdict;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GuardsConfigurationTest {

    @Test
    void loadsGuardsWithAllMatcherShapes(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("guards.yaml");
        Files.writeString(file, """
                guards:
                  - name: equals-shape
                    when: before
                    match:
                      severity: CRITICAL
                    action: block
                  - name: in-shape
                    when: before
                    match:
                      packageName: [foo, bar]
                    action: manual_review
                  - name: comparison-shape
                    when: after
                    match:
                      attempt: { gte: 2 }
                    action: block
                """);

        List<GuardRule> rules = ConfigLoader.yaml().load(file, GuardsConfiguration.class).guards();

        assertEquals(3, rules.size());

        GuardRule equalsRule = rules.get(0);
        assertEquals("equals-shape", equalsRule.name());
        assertEquals(GuardRule.When.BEFORE, equalsRule.when());
        assertEquals(Map.of("severity", "CRITICAL"), equalsRule.match());
        assertEquals(Verdict.BLOCK, equalsRule.action());

        GuardRule inRule = rules.get(1);
        assertEquals(Map.of("packageName", List.of("foo", "bar")), inRule.match());
        assertEquals(Verdict.MANUAL_REVIEW, inRule.action());

        GuardRule comparisonRule = rules.get(2);
        assertEquals(GuardRule.When.AFTER, comparisonRule.when());
        assertEquals(Map.of("attempt", Map.of("gte", 2)), comparisonRule.match());
    }

    @Test
    void missingFileThrowsLoadException(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("does-not-exist.yaml");

        ConfigLoadException ex = assertThrows(ConfigLoadException.class,
                () -> ConfigLoader.yaml().load(missing, GuardsConfiguration.class));

        assertTrue(ex.getMessage().toLowerCase().contains("not found"));
    }

    @Test
    void malformedYamlThrowsLoadException(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("guards.yaml");
        Files.writeString(file, "guards:\n  - name: bad\n  when: before\n    action: [broken");

        assertThrows(ConfigLoadException.class, () -> ConfigLoader.yaml().load(file, GuardsConfiguration.class));
    }

    @Test
    void missingRequiredNameThrowsLoadException(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("guards.yaml");
        Files.writeString(file, """
                guards:
                  - when: before
                    match:
                      severity: CRITICAL
                    action: block
                """);

        assertThrows(ConfigLoadException.class, () -> ConfigLoader.yaml().load(file, GuardsConfiguration.class));
    }

    @Test
    void unrecognizedWhenValueThrowsLoadException(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("guards.yaml");
        Files.writeString(file, """
                guards:
                  - name: bad-when
                    when: sometimes
                    action: block
                """);

        assertThrows(ConfigLoadException.class, () -> ConfigLoader.yaml().load(file, GuardsConfiguration.class));
    }

    @Test
    void whenAndActionAreCaseInsensitive(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("guards.yaml");
        Files.writeString(file, """
                guards:
                  - name: mixed-case
                    when: BeFoRe
                    action: MaNuAl_ReViEw
                """);

        GuardRule rule = ConfigLoader.yaml().load(file, GuardsConfiguration.class).guards().getFirst();

        assertEquals(GuardRule.When.BEFORE, rule.when());
        assertEquals(Verdict.MANUAL_REVIEW, rule.action());
    }

    @Test
    void thePackagedGuardsSendAnAgentWritingToVersionControlOrCiToManualReview() throws Exception {
        // The shipped policy, not a fixture: deleting the rule from guards.yaml fails here.
        AgentGuards guards = new AgentGuards(
                ConfigLoader.yaml().loadResource("/guards.yaml", GuardsConfiguration.class).guards());
        Finding finding = new Finding("F-1", "CVE-0000-0000", Severity.HIGH, "inventory-api",
                "example:example", "1.0", "direct", null, 5, "n/a");

        for (String path : List.of(".git/config", ".github/workflows/ci.yml", ".mvn/extensions.xml",
                "settings.xml", "nested/module/.git/hooks/pre-commit")) {
            GuardRule matched = guards.matchingToolRule(new ToolCall("writeFile", path, "body"), finding);
            assertEquals(Verdict.MANUAL_REVIEW, matched == null ? Verdict.ALLOW : matched.action(),
                    path + " should reach manual review");
        }
        assertNull(guards.matchingToolRule(new ToolCall("writeFile", "pom.xml", "<project/>"), finding),
                "the remediation's own pom.xml write must stay allowed");
    }
}
