package com.example.securityharness.remediation;

import com.example.securityharness.buildgate.BuildGateResult;
import com.example.securityharness.findings.Finding;
import com.example.securityharness.findings.Severity;
import com.example.securityharness.guards.GuardDecision;
import com.example.securityharness.guards.GuardRule;
import com.example.securityharness.policy.Verdict;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContextTest {

    static Finding finding(String id, String fixedVersion) {
        return new Finding(id, "CVE-0000-0000", Severity.HIGH, "inventory-api",
                "example:example", "1.0", "direct", fixedVersion, 1, "n/a");
    }

    @Test
    void startsUnfinishedOnTheFirstFinding() {
        Context context = new Context(List.of(finding("F-1", "1.1")));

        assertNull(context.getOutcome(), "a run that has not finished has no outcome yet");
        assertTrue(context.hasCurrentFinding());
        assertEquals("F-1", context.currentFinding().id());
    }

    @Test
    void recordOutcomeAdvancesToNextFindingAndResetsAttempt() {
        Context context = new Context(
                List.of(finding("F-1", "1.1"), finding("F-2", null)));
        context.startAttempts();

        context.recordOutcome(Outcome.SUCCESS);

        assertEquals("F-2", context.currentFinding().id());
        assertEquals(0, context.getAttempt());
        assertEquals(Map.of("F-1", Outcome.SUCCESS), context.getOutcomes());
    }

    @Test
    void outcomesKeepInsertionOrder() {
        Context context = new Context(
                List.of(finding("F-1", "1.1"), finding("F-2", null)));

        context.recordOutcome(Outcome.NEEDS_ATTENTION);
        context.recordOutcome(Outcome.SUCCESS);

        assertEquals(List.of("F-1", "F-2"), List.copyOf(context.getOutcomes().keySet()));
    }

    @Test
    void hasCurrentFindingIsFalseWhenListExhausted() {
        Context context = new Context(List.of(finding("F-1", "1.1")));

        context.recordOutcome(Outcome.SUCCESS);

        assertFalse(context.hasCurrentFinding());
        assertThrows(IllegalStateException.class, context::currentFinding);
    }

    @Test
    void attemptsAreExhaustedAtMaxAttempts() {
        Context context = new Context(List.of(finding("F-1", "1.1")), 2);

        context.startAttempts();
        assertEquals(1, context.getAttempt());
        assertFalse(context.attemptsExhausted());

        context.nextAttempt();
        assertEquals(2, context.getAttempt());
        assertTrue(context.attemptsExhausted());
    }

    @Test
    void defaultMaxAttemptsIsThree() {
        assertEquals(3, new Context(List.of(finding("F-1", "1.1"))).getMaxAttempts());
    }

    @Test
    void rejectsMaxAttemptsBelowOne() {
        assertThrows(IllegalArgumentException.class,
                () -> new Context(List.of(finding("F-1", "1.1")), 0));
    }

    @Test
    void aRecordedOutcomeKeepsTheStrategyAndAttemptCountTheContextItselfThrowsAway() {
        Context context = new Context(List.of(finding("F-1", null)));
        context.setStrategy(Strategy.AGENT_REMEDIATION);
        context.startAttempts();
        context.nextAttempt();
        context.setVerified(true);

        context.recordOutcome(Outcome.SUCCESS);

        FindingRecord record = context.getRecords().get(0);
        assertEquals("F-1", record.id());
        assertEquals("CVE-0000-0000", record.cve());
        assertEquals(Severity.HIGH, record.severity());
        assertEquals("example:example", record.packageName());
        assertEquals(Strategy.AGENT_REMEDIATION, record.strategy());
        assertEquals(2, record.attempts());
        assertTrue(record.verified());
        assertEquals(Outcome.SUCCESS, record.outcome());
        // The live fields are cleared, which is exactly why the record has to exist.
        assertEquals(0, context.getAttempt());
        assertNull(context.getStrategy());
    }

    @Test
    void guardDecisionsAndChangedFilesAreFiledAgainstTheFindingTheyBelongTo() {
        Context context = new Context(
                List.of(finding("F-1", null), finding("F-2", null)));

        context.recordGuardDecision(GuardRule.When.BEFORE, null, Verdict.ALLOW);
        context.recordGuardDecision(GuardRule.When.AFTER, "distrust-flaky", Verdict.MANUAL_REVIEW);
        context.addFileChanged("pom.xml");
        context.recordOutcome(Outcome.NEEDS_ATTENTION);

        context.recordOutcome(Outcome.SUCCESS);

        FindingRecord first = context.getRecords().get(0);
        assertEquals(List.of(
                        new GuardDecision(GuardRule.When.BEFORE, null, Verdict.ALLOW),
                        new GuardDecision(GuardRule.When.AFTER, "distrust-flaky", Verdict.MANUAL_REVIEW)),
                first.guardDecisions());
        assertEquals(List.of("pom.xml"), first.filesChanged());

        FindingRecord second = context.getRecords().get(1);
        assertEquals(List.of(), second.guardDecisions(), "the previous finding's guards must not leak");
        assertEquals(List.of(), second.filesChanged(), "the previous finding's writes must not leak");
        assertFalse(second.verified(), "verification state must not leak either");
    }

    @Test
    void findingCountCoversFindingsTheRunNeverReached() {
        Context context = new Context(
                List.of(finding("F-1", "1.1"), finding("F-2", null)));

        context.recordOutcome(Outcome.SUCCESS);

        assertEquals(2, context.findingCount());
        assertEquals(1, context.getRecords().size());
    }

    @Test
    void theBuildGateResultIsAbsentUntilTheGateRuns() {
        Context context = new Context(List.of(finding("F-1", "1.1")));

        assertNull(context.getBuildGate());

        context.setBuildGate(new BuildGateResult(Verdict.ALLOW, List.of(), List.of()));
        assertEquals(Verdict.ALLOW, context.getBuildGate().action());
    }

    @Test
    void stacksAreEmptyUntilTheyAreDetected() {
        assertEquals(List.of(), new Context(List.of(finding("F-1", "1.1"))).getStacks(),
                "a run that has not been detected yet claims no stack, rather than null");
    }

    @Test
    void detectedStacksAreHeldForTheWholeRun() {
        Context context = new Context(List.of(finding("F-1", "1.1"), finding("F-2", "2.0")));
        context.setStacks(List.of("java"));
        context.startAttempts();

        context.recordOutcome(Outcome.SUCCESS);

        assertEquals(List.of("java"), context.getStacks(),
                "the stack is a fact about the service, not a per-finding buffer");
    }

    @Test
    void detectedStacksAreCopiedRatherThanAliased() {
        Context context = new Context(List.of(finding("F-1", "1.1")));
        List<String> detected = new ArrayList<>(List.of("java"));
        context.setStacks(detected);

        detected.add("python");

        assertEquals(List.of("java"), context.getStacks());
    }

    @Test
    void aFindingIsNotEscalatedUntilSomethingEscalatesIt() {
        Context context = new Context(List.of(finding("F-1", "1.1")));
        context.setStrategy(Strategy.DEPENDENCY_UPDATE);

        assertFalse(context.isEscalated());
    }

    @Test
    void escalatingHandsTheFindingToTheAgent() {
        Context context = new Context(List.of(finding("F-1", "1.1")));
        context.setStrategy(Strategy.DEPENDENCY_UPDATE);

        context.escalateToAgent();

        assertEquals(Strategy.AGENT_REMEDIATION, context.getStrategy());
        assertTrue(context.isEscalated());
    }

    @Test
    void escalationIsAFactAboutOneFindingAndDoesNotOutliveIt() {
        Context context = new Context(List.of(finding("F-1", "1.1"), finding("F-2", "2.0")));
        context.setStrategy(Strategy.DEPENDENCY_UPDATE);
        context.startAttempts();
        context.escalateToAgent();

        context.recordOutcome(Outcome.SUCCESS);

        assertFalse(context.isEscalated(), "the next finding starts on its own strategy");
    }

    @Test
    void theRecordKeepsThatAFindingWasEscalated() {
        Context context = new Context(List.of(finding("F-1", "1.1")));
        context.setStrategy(Strategy.DEPENDENCY_UPDATE);
        context.startAttempts();
        context.escalateToAgent();
        context.nextAttempt();

        context.recordOutcome(Outcome.SUCCESS);

        FindingRecord record = context.getRecords().get(0);
        assertEquals(Strategy.AGENT_REMEDIATION, record.strategy());
        assertTrue(record.escalated(), "a direct finding recorded as the agent's needs to say why");
        assertEquals(2, record.attempts());
    }

    @Test
    void aFindingNothingWroteForHasNoFilesChanged() {
        Context context = new Context(List.of(finding("F-1", "1.1")));

        assertFalse(context.hasFilesChanged());

        context.addFileChanged("pom.xml");

        assertTrue(context.hasFilesChanged());
    }
}
