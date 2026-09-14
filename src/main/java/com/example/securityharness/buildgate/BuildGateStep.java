package com.example.securityharness.buildgate;

import com.example.securityharness.policy.Verdict;

public record BuildGateStep(String name, String command, Verdict onFailure) {

    public BuildGateStep {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Build gate step is missing a name");
        }
        if (command == null || command.isBlank()) {
            throw new IllegalArgumentException("Build gate step '" + name + "' is missing a command");
        }
        if (onFailure == null) {
            throw new IllegalArgumentException("Build gate step '" + name + "' is missing 'onFailure'");
        }
    }
}
