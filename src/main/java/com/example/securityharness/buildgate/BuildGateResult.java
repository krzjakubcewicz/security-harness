package com.example.securityharness.buildgate;

import com.example.securityharness.policy.Verdict;

import java.util.List;

/**
 * What the build gate ran and what it decided. {@code stacks} names the stacks detected in the
 * service directory - empty means nothing was detected, which is why no step ran. {@code steps}
 * holds only the steps that actually ran: a BLOCK failure stops the gate, so anything after it
 * is genuinely unknown, not passed.
 */
public record BuildGateResult(Verdict action, List<String> stacks, List<StepResult> steps) {

    /** Exit code -1 means the command could not be started or was interrupted. */
    public record StepResult(String name, boolean passed, int exitCode) {
    }

    public BuildGateResult {
        stacks = List.copyOf(stacks);
        steps = List.copyOf(steps);
    }
}
