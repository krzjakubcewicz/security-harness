package com.example.securityharness.autonomy;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AutonomyActionTest {

    @Test
    void escalationOrdersFromMergingItselfToFilingATicket() {
        assertEquals(AutonomyAction.PULL_REQUEST,
                AutonomyAction.AUTO_MERGE.strictest(AutonomyAction.PULL_REQUEST));
        assertEquals(AutonomyAction.SLACK,
                AutonomyAction.SLACK.strictest(AutonomyAction.PULL_REQUEST));
        assertEquals(AutonomyAction.JIRA,
                AutonomyAction.SLACK.strictest(AutonomyAction.JIRA));
    }

    @Test
    void doingNothingIsNoDemandAndLosesToEverything() {
        assertEquals(AutonomyAction.AUTO_MERGE,
                AutonomyAction.NONE.strictest(AutonomyAction.AUTO_MERGE));
        assertEquals(AutonomyAction.JIRA,
                AutonomyAction.JIRA.strictest(AutonomyAction.NONE));
        assertEquals(AutonomyAction.NONE,
                AutonomyAction.NONE.strictest(AutonomyAction.NONE));
    }

    @Test
    void anActionComparedWithItselfIsItself() {
        assertEquals(AutonomyAction.SLACK, AutonomyAction.SLACK.strictest(AutonomyAction.SLACK));
    }
}
