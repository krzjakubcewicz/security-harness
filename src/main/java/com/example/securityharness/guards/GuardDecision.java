package com.example.securityharness.guards;

import com.example.securityharness.policy.Verdict;

/**
 * One guard verdict on one finding, kept for the run report. {@code rule} is null when no rule
 * matched - the implicit ALLOW - so the report can tell "nothing matched" from "a rule said yes".
 */
public record GuardDecision(GuardRule.When phase, String rule, Verdict action) {
}
