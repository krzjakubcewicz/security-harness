package com.example.securityharness.guards;

import com.example.securityharness.policy.Verdict;

import java.util.Map;

public record GuardRule(String name, When when, Map<String, Object> match, Verdict action) {

    public enum When {
        BEFORE,
        AFTER,
        /** Evaluated once per tool call the agent asks for, before any of them is applied. */
        TOOL
    }

    public GuardRule {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Guard rule is missing a name");
        }
        if (when == null) {
            throw new IllegalArgumentException("Guard '" + name + "' is missing 'when'");
        }
        if (action == null) {
            throw new IllegalArgumentException("Guard '" + name + "' is missing 'action'");
        }
        match = match == null ? Map.of() : Map.copyOf(match);
    }
}
