package com.example.securityharness.guards;

import com.example.securityharness.agent.ToolCall;
import com.example.securityharness.config.ConfigLoadException;
import com.example.securityharness.config.ConfigLoader;
import com.example.securityharness.findings.Finding;
import com.example.securityharness.findings.Severity;
import com.example.securityharness.policy.Verdict;
import com.example.securityharness.remediation.Context;
import com.example.securityharness.remediation.Strategy;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AgentGuardsTest {

    static Finding finding(String id, Severity severity, String packageName, int slaDaysRemaining) {
        return new Finding(id, "CVE-0000-0000", severity, "inventory-api",
                packageName, "1.0", "direct", null, slaDaysRemaining, "n/a");
    }

    static Context contextAtAttempt(Finding finding, int attempt) {
        Context context = new Context(List.of(finding));
        context.setStrategy(Strategy.AGENT_REMEDIATION);
        context.startAttempts();
        for (int i = 1; i < attempt; i++) {
            context.nextAttempt();
        }
        return context;
    }

    static GuardRule rule(String name, GuardRule.When when, Map<String, Object> match, Verdict action) {
        return new GuardRule(name, when, match, action);
    }

    static ToolCall write(String filePath) {
        return new ToolCall("writeFile", filePath, "body");
    }

    /** The action a tool rule imposes on this path, or ALLOW when no rule trips. */
    static Verdict toolAction(AgentGuards guards, String filePath, Finding finding) {
        GuardRule matched = guards.matchingToolRule(write(filePath), finding);
        return matched == null ? Verdict.ALLOW : matched.action();
    }

    @Test
    void noRulesAlwaysAllowsBeforeAndAfter() {
        AgentGuards guards = new AgentGuards();
        Finding f = finding("F-1", Severity.CRITICAL, "example:example", -5);
        Context context = contextAtAttempt(f, 1);

        assertEquals(Verdict.ALLOW, guards.evaluateBefore(f, context));
        assertEquals(Verdict.ALLOW, guards.evaluateAfter(f, context));
    }

    @Test
    void noMatchingRuleAllows() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("only-high", GuardRule.When.BEFORE, Map.of("severity", "HIGH"), Verdict.BLOCK)));
        Finding f = finding("F-1", Severity.CRITICAL, "example:example", 5);

        assertEquals(Verdict.ALLOW, guards.evaluateBefore(f, contextAtAttempt(f, 1)));
    }

    @Test
    void firstMatchingRuleWinsOverLaterRules() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("first", GuardRule.When.BEFORE, Map.of("severity", "CRITICAL"), Verdict.MANUAL_REVIEW),
                rule("second", GuardRule.When.BEFORE, Map.of("severity", "CRITICAL"), Verdict.BLOCK)));
        Finding f = finding("F-1", Severity.CRITICAL, "example:example", 5);

        assertEquals(Verdict.MANUAL_REVIEW, guards.evaluateBefore(f, contextAtAttempt(f, 1)));
    }

    @Test
    void equalsMatchOnSeverityBlocks() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("block-critical", GuardRule.When.BEFORE, Map.of("severity", "CRITICAL"), Verdict.BLOCK)));

        Finding critical = finding("F-1", Severity.CRITICAL, "example:example", 5);
        Finding high = finding("F-2", Severity.HIGH, "example:example", 5);

        assertEquals(Verdict.BLOCK, guards.evaluateBefore(critical, contextAtAttempt(critical, 1)));
        assertEquals(Verdict.ALLOW, guards.evaluateBefore(high, contextAtAttempt(high, 1)));
    }

    @Test
    void inListMatchOnPackageNameTriggersManualReview() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("flaky-packages", GuardRule.When.BEFORE,
                        Map.of("packageName", List.of("foo", "bar")), Verdict.MANUAL_REVIEW)));

        Finding match = finding("F-1", Severity.HIGH, "bar", 5);
        Finding noMatch = finding("F-2", Severity.HIGH, "baz", 5);

        assertEquals(Verdict.MANUAL_REVIEW, guards.evaluateBefore(match, contextAtAttempt(match, 1)));
        assertEquals(Verdict.ALLOW, guards.evaluateBefore(noMatch, contextAtAttempt(noMatch, 1)));
    }

    @Test
    void numericComparisonSupportsGtGteLtLte() {
        AgentGuards ltGuard = new AgentGuards(List.of(
                rule("overdue", GuardRule.When.BEFORE, Map.of("slaDaysRemaining", Map.of("lt", 0)), Verdict.BLOCK)));
        Finding overdue = finding("F-1", Severity.HIGH, "example:example", -1);
        Finding onTime = finding("F-2", Severity.HIGH, "example:example", 1);
        assertEquals(Verdict.BLOCK, ltGuard.evaluateBefore(overdue, contextAtAttempt(overdue, 1)));
        assertEquals(Verdict.ALLOW, ltGuard.evaluateBefore(onTime, contextAtAttempt(onTime, 1)));

        AgentGuards gteGuard = new AgentGuards(List.of(
                rule("too-many-attempts", GuardRule.When.BEFORE, Map.of("attempt", Map.of("gte", 2)), Verdict.BLOCK)));
        Finding f = finding("F-3", Severity.HIGH, "example:example", 1);
        assertEquals(Verdict.ALLOW, gteGuard.evaluateBefore(f, contextAtAttempt(f, 1)));
        assertEquals(Verdict.BLOCK, gteGuard.evaluateBefore(f, contextAtAttempt(f, 2)));
    }

    @Test
    void beforeRulesDoNotFireOnEvaluateAfterAndViceVersa() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("before-only", GuardRule.When.BEFORE, Map.of(), Verdict.BLOCK),
                rule("after-only", GuardRule.When.AFTER, Map.of(), Verdict.MANUAL_REVIEW)));
        Finding f = finding("F-1", Severity.HIGH, "example:example", 5);
        Context context = contextAtAttempt(f, 1);

        assertEquals(Verdict.BLOCK, guards.evaluateBefore(f, context));
        assertEquals(Verdict.MANUAL_REVIEW, guards.evaluateAfter(f, context));
    }

    @Test
    void verifyPassedIsAvailableOnlyThroughEvaluateAfter() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("only-when-verified", GuardRule.When.AFTER, Map.of("verifyPassed", true), Verdict.MANUAL_REVIEW)));
        Finding f = finding("F-1", Severity.HIGH, "example:example", 5);
        Context context = contextAtAttempt(f, 1);

        assertEquals(Verdict.MANUAL_REVIEW, guards.evaluateAfter(f, context));
    }

    @Test
    void unknownMatchFieldThrowsIllegalArgumentException() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("typo", GuardRule.When.BEFORE, Map.of("severityy", "CRITICAL"), Verdict.BLOCK)));
        Finding f = finding("F-1", Severity.CRITICAL, "example:example", 5);

        assertThrows(IllegalArgumentException.class, () -> guards.evaluateBefore(f, contextAtAttempt(f, 1)));
    }

    @Test
    void toolRuleMatchesAnySegmentOfTheAgentsPath() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("protect-version-control", GuardRule.When.TOOL,
                        Map.of("pathSegment", List.of(".git", ".github", ".mvn", "settings.xml")),
                        Verdict.MANUAL_REVIEW)));
        Finding f = finding("F-1", Severity.HIGH, "example:example", 5);

        assertEquals(Verdict.MANUAL_REVIEW, toolAction(guards, ".git/config", f));
        assertEquals(Verdict.MANUAL_REVIEW, toolAction(guards, "nested/module/.git/hooks/pre-commit", f));
        assertEquals(Verdict.MANUAL_REVIEW, toolAction(guards, ".github/workflows/ci.yml", f));
        assertEquals(Verdict.MANUAL_REVIEW, toolAction(guards, "settings.xml", f));
        assertEquals(Verdict.ALLOW, toolAction(guards, "pom.xml", f));
        assertEquals(Verdict.ALLOW, toolAction(guards, "src/main/java/App.java", f));
    }

    @Test
    void toolRuleSegmentMatchIgnoresCase() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("protect-version-control", GuardRule.When.TOOL,
                        Map.of("pathSegment", ".git"), Verdict.BLOCK)));
        Finding f = finding("F-1", Severity.HIGH, "example:example", 5);

        assertEquals(Verdict.BLOCK, toolAction(guards, ".GIT/config", f));
    }

    @Test
    void toolRuleSegmentDoesNotMatchAPartialSegment() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("protect-version-control", GuardRule.When.TOOL,
                        Map.of("pathSegment", ".git"), Verdict.BLOCK)));
        Finding f = finding("F-1", Severity.HIGH, "example:example", 5);

        assertEquals(Verdict.ALLOW, toolAction(guards, ".gitignore", f));
        assertEquals(Verdict.ALLOW, toolAction(guards, "src/.gitkeep", f));
    }

    @Test
    void toolRulesCombineThePathWithFindingFields() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("only-on-high", GuardRule.When.TOOL,
                        Map.of("pathSegment", ".git", "severity", "HIGH"), Verdict.BLOCK)));

        Finding high = finding("F-1", Severity.HIGH, "example:example", 5);
        Finding medium = finding("F-2", Severity.MEDIUM, "example:example", 5);

        assertEquals(Verdict.BLOCK, toolAction(guards, ".git/config", high));
        assertEquals(Verdict.ALLOW, toolAction(guards, ".git/config", medium));
    }

    @Test
    void beforeAndAfterRulesDoNotFireOnToolCallsAndViceVersa() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("before-only", GuardRule.When.BEFORE, Map.of(), Verdict.BLOCK),
                rule("tool-only", GuardRule.When.TOOL, Map.of("pathSegment", ".git"), Verdict.MANUAL_REVIEW)));
        Finding f = finding("F-1", Severity.HIGH, "example:example", 5);

        assertEquals(Verdict.MANUAL_REVIEW, toolAction(guards, ".git/config", f));
        assertEquals(Verdict.BLOCK, guards.evaluateBefore(f, contextAtAttempt(f, 1)));
    }

    @Test
    void pathSegmentOutsideAToolRuleThrowsIllegalArgumentException() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("misplaced", GuardRule.When.BEFORE, Map.of("pathSegment", ".git"), Verdict.BLOCK)));
        Finding f = finding("F-1", Severity.HIGH, "example:example", 5);

        assertThrows(IllegalArgumentException.class, () -> guards.evaluateBefore(f, contextAtAttempt(f, 1)));
    }

    @Test
    void attemptInsideAToolRuleThrowsIllegalArgumentExceptionBecauseTheToolLayerHasNoContext() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("needs-context", GuardRule.When.TOOL, Map.of("attempt", Map.of("gte", 2)), Verdict.BLOCK)));
        Finding f = finding("F-1", Severity.HIGH, "example:example", 5);

        assertThrows(IllegalArgumentException.class, () -> toolAction(guards, "pom.xml", f));
    }

    @Test
    void comparisonOnNonNumericFieldThrowsIllegalArgumentException() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("bad-comparison", GuardRule.When.BEFORE, Map.of("severity", Map.of("gt", 1)), Verdict.BLOCK)));
        Finding f = finding("F-1", Severity.CRITICAL, "example:example", 5);

        assertThrows(IllegalArgumentException.class, () -> guards.evaluateBefore(f, contextAtAttempt(f, 1)));
    }

    @Test
    void theMatchedBeforeRuleIsNamedSoTheRunReportCanSayWhichOneFired() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("block-criticals", GuardRule.When.BEFORE, Map.of("severity", "CRITICAL"), Verdict.BLOCK)));
        Finding f = finding("F-1", Severity.CRITICAL, "example:example", 5);

        GuardRule matched = guards.matchingBeforeRule(f, contextAtAttempt(f, 1));

        assertEquals("block-criticals", matched.name());
        assertEquals(Verdict.BLOCK, AgentGuards.actionOf(matched));
    }

    @Test
    void theMatchedAfterRuleIsNamedToo() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("distrust-flaky", GuardRule.When.AFTER, Map.of("packageName", "example:example"),
                        Verdict.MANUAL_REVIEW)));
        Finding f = finding("F-1", Severity.HIGH, "example:example", 5);

        assertEquals("distrust-flaky", guards.matchingAfterRule(f, contextAtAttempt(f, 1)).name());
    }

    @Test
    void nothingMatchingIsANullRuleAndAnImplicitAllow() {
        AgentGuards guards = new AgentGuards(List.of(
                rule("block-criticals", GuardRule.When.BEFORE, Map.of("severity", "CRITICAL"), Verdict.BLOCK)));
        Finding f = finding("F-1", Severity.LOW, "example:example", 5);

        assertNull(guards.matchingBeforeRule(f, contextAtAttempt(f, 1)));
        assertEquals(Verdict.ALLOW, AgentGuards.actionOf(null));
    }

    @Test
    void theShippedGuardsRefuseAReadOfACredentialFile() throws Exception {
        AgentGuards guards = new AgentGuards(shippedRules());

        GuardRule matched = guards.matchingToolRule(new ToolCall("readFile", ".env", null),
                finding("F-1", Severity.HIGH, "example:example", 5));

        assertNotNull(matched, ".env holds credentials, not source");
        assertEquals(Verdict.MANUAL_REVIEW, matched.action());
    }

    @Test
    void theShippedGuardsStillAllowAnOrdinaryRead() throws Exception {
        AgentGuards guards = new AgentGuards(shippedRules());

        assertNull(guards.matchingToolRule(new ToolCall("readFile", "src/main/java/App.java", null),
                finding("F-1", Severity.HIGH, "example:example", 5)));
    }

    /** The rules the harness actually ships, not a fixture: these two assert about policy. */
    private static List<GuardRule> shippedRules() throws ConfigLoadException {
        return ConfigLoader.yaml().loadResource("/guards.yaml", GuardsConfiguration.class).guards();
    }
}
