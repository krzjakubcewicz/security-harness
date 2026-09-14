package com.example.securityharness.remediation;

/**
 * How a finding, or a whole service run, ended. Two answers: it was resolved, or a person has to
 * look at it. Why a person has to look is in the finding's record, not in this enum.
 */
public enum Outcome {
    SUCCESS,
    NEEDS_ATTENTION
}
