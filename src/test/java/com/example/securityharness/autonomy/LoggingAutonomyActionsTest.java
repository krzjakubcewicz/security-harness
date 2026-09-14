package com.example.securityharness.autonomy;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoggingAutonomyActionsTest {

    private static String describe(AutonomyAction action) {
        return LoggingAutonomyActions.describe("inventory-api",
                new AutonomyDecision("a-rule", action, "F-1", "F-1 a:b 1.0.0 -> 1.0.1 (PATCH, DEPENDENCY_FILE_ONLY)"));
    }

    @Test
    void everyActionSaysWhatItWouldDoAndToWhichService() {
        assertTrue(describe(AutonomyAction.AUTO_MERGE).contains("inventory-api"));
        assertTrue(describe(AutonomyAction.AUTO_MERGE).toLowerCase().contains("merge"));
        assertTrue(describe(AutonomyAction.PULL_REQUEST).toLowerCase().contains("pull request"));
        assertTrue(describe(AutonomyAction.SLACK).toLowerCase().contains("slack"));
        assertTrue(describe(AutonomyAction.JIRA).toLowerCase().contains("jira"));
    }

    @Test
    void everyDescriptionSaysItIsAStubSoNobodyReadsItAsDone() {
        for (AutonomyAction action : AutonomyAction.values()) {
            assertTrue(describe(action).startsWith("would "), describe(action));
        }
    }

    @Test
    void doingNothingSaysSoRatherThanClaimingAnAction() {
        assertEquals("would do nothing for inventory-api", describe(AutonomyAction.NONE));
    }

    @Test
    void aDecisionCarryingAWarningSaysSoLoudlyAndOnItsOwnLine() {
        String alarm = LoggingAutonomyActions.alarm(new AutonomyDecision("a-finding-a-human-must-read",
                AutonomyAction.PULL_REQUEST, "F-1", "F-1 a:b 1.0.0 -> 1.0.1 (PATCH, SOURCE_CODE)",
                "TESTS LOST: F-1 left 12 tests that will run where there were 15"));

        assertTrue(alarm.startsWith("!! "), alarm);
        assertTrue(alarm.contains("TESTS LOST"), alarm);
        assertTrue(alarm.contains("F-1"), alarm);
    }

    @Test
    void anOrdinaryDecisionAddsNothing() {
        assertNull(LoggingAutonomyActions.alarm(new AutonomyDecision("a-rule",
                AutonomyAction.PULL_REQUEST, "F-1", "F-1 a:b 1.0.0 -> 1.0.1 (PATCH, SOURCE_CODE)")));
    }
}
