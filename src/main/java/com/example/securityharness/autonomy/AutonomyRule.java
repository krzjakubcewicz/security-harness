package com.example.securityharness.autonomy;

import java.util.Map;

/**
 * One rule from autonomy.yaml. Deliberately the same shape as guards.yaml's GuardRule - a reader
 * who knows one file can read the other - minus 'when': a gate is evaluated at exactly one moment,
 * when a service is finished.
 */
public record AutonomyRule(String name, Map<String, Object> match, AutonomyAction action) {

    public AutonomyRule {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Autonomy gate is missing a name");
        }
        if (action == null) {
            throw new IllegalArgumentException("Autonomy gate '" + name + "' is missing 'action'");
        }
        match = match == null ? Map.of() : Map.copyOf(match);
    }
}
