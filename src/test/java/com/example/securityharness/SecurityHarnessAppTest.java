package com.example.securityharness;

import com.example.securityharness.findings.Finding;
import com.example.securityharness.findings.Severity;
import com.example.securityharness.remediation.Context;
import com.example.securityharness.remediation.Outcome;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityHarnessAppTest {

    @Test
    void parsesVulnerabilitiesFlag() {
        assertEquals("findings.json",
                SecurityHarnessApp.parseArg(new String[]{"--vulnerabilities", "findings.json"}, "--vulnerabilities"));
    }

    @Test
    void parsesReposFlag() {
        assertEquals("/repos",
                SecurityHarnessApp.parseArg(new String[]{"--vulnerabilities", "f.json", "--repos", "/repos"}, "--repos"));
    }

    @Test
    void returnsNullWhenFlagMissing() {
        assertNull(SecurityHarnessApp.parseArg(new String[]{}, "--vulnerabilities"));
    }

    @Test
    void returnsNullWhenFlagHasNoValue() {
        assertNull(SecurityHarnessApp.parseArg(new String[]{"--vulnerabilities"}, "--vulnerabilities"));
    }

    @Test
    void returnsNullForUnknownFlag() {
        assertNull(SecurityHarnessApp.parseArg(new String[]{"--unknown", "x"}, "--vulnerabilities"));
    }

    @Test
    void aValuelessFlagIsFoundByItsPresence() {
        assertTrue(SecurityHarnessApp.hasFlag(
                new String[]{"--vulnerabilities", "f.json", "--no-verify-changes"}, "--no-verify-changes"));
    }

    @Test
    void changeVerificationIsOnUnlessTheFlagIsThere() {
        assertFalse(SecurityHarnessApp.hasFlag(
                new String[]{"--vulnerabilities", "f.json"}, "--no-verify-changes"));
    }

    private static Finding finding(String id, String fixedVersion) {
        return finding(id, fixedVersion, "inventory-api");
    }

    private static Finding finding(String id, String fixedVersion, String service) {
        return new Finding(id, "CVE-0000-0000", Severity.HIGH, service,
                "example:example", "1.0", "direct", fixedVersion, 1, "n/a");
    }

    private static Map<String, Context> contexts(Object... serviceThenContext) {
        Map<String, Context> contexts = new LinkedHashMap<>();
        for (int i = 0; i < serviceThenContext.length; i += 2) {
            contexts.put((String) serviceThenContext[i], (Context) serviceThenContext[i + 1]);
        }
        return contexts;
    }

    @Test
    void groupsFindingsByServiceInReportOrder() {
        Map<String, List<Finding>> groups = SecurityHarnessApp.groupByService(List.of(
                finding("F-1", "1.1", "inventory-api"),
                finding("F-2", "5.4", "report-worker"),
                finding("F-3", null, "inventory-api")));

        assertEquals(List.of("inventory-api", "report-worker"), List.copyOf(groups.keySet()));
        assertEquals(List.of("F-1", "F-3"), groups.get("inventory-api").stream().map(Finding::id).toList());
        assertEquals(List.of("F-2"), groups.get("report-worker").stream().map(Finding::id).toList());
    }

    @Test
    void groupsFindingsWithoutAServiceUnderUnknown() {
        Map<String, List<Finding>> groups = SecurityHarnessApp.groupByService(
                List.of(finding("F-1", "1.1", null)));

        assertEquals(List.of(SecurityHarnessApp.UNKNOWN_SERVICE), List.copyOf(groups.keySet()));
    }

    @Test
    void reportReturnsZeroWhenEveryFindingSucceeded() {
        Context context = new Context(List.of(finding("F-1", "1.1")));
        context.recordOutcome(Outcome.SUCCESS);
        context.finish(Outcome.SUCCESS);

        assertEquals(0, SecurityHarnessApp.report(contexts("inventory-api", context)));
    }

    @Test
    void reportReturnsOneWhenAFindingNeedsAttention() {
        Context context = new Context(
                List.of(finding("F-1", "1.1"), finding("F-2", null)));
        context.recordOutcome(Outcome.SUCCESS);
        context.recordOutcome(Outcome.NEEDS_ATTENTION);
        context.finish(Outcome.SUCCESS);

        assertEquals(1, SecurityHarnessApp.report(contexts("inventory-api", context)));
    }

    @Test
    void reportReturnsOneWhenTheWorkflowNeedsAttention() {
        Context context = new Context(List.of(finding("F-1", "1.1")));
        context.finish(Outcome.NEEDS_ATTENTION);

        assertEquals(1, SecurityHarnessApp.report(contexts("inventory-api", context)));
    }

    @Test
    void reportReturnsOneWhenTheBuildGateEndedTheRunInManualReview() {
        Context context = new Context(List.of(finding("F-1", "1.1")));
        context.recordOutcome(Outcome.SUCCESS);
        context.finish(Outcome.NEEDS_ATTENTION);

        assertEquals(1, SecurityHarnessApp.report(contexts("inventory-api", context)));
    }

    @Test
    void reportReturnsOneWhenOneServiceNeedsAttentionAndAnotherSucceeded() {
        Context clean = new Context(List.of(finding("F-1", "1.1")));
        clean.recordOutcome(Outcome.SUCCESS);
        clean.finish(Outcome.SUCCESS);

        Context failed = new Context(List.of(finding("F-2", "5.4", "report-worker")));
        failed.finish(Outcome.NEEDS_ATTENTION);

        assertEquals(1, SecurityHarnessApp.report(contexts("inventory-api", clean, "report-worker", failed)));
    }

    @Test
    void reportReturnsZeroWhenEveryServiceIsClean() {
        Context inventory = new Context(List.of(finding("F-1", "1.1")));
        inventory.recordOutcome(Outcome.SUCCESS);
        inventory.finish(Outcome.SUCCESS);

        Context worker = new Context(List.of(finding("F-2", "5.4", "report-worker")));
        worker.recordOutcome(Outcome.SUCCESS);
        worker.finish(Outcome.SUCCESS);

        assertEquals(0, SecurityHarnessApp.report(contexts("inventory-api", inventory, "report-worker", worker)));
    }
}
