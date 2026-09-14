package com.example.securityharness.autonomy;

import java.util.List;

/**
 * The root of autonomy.yaml. An empty list is not a policy that allows everything - it means the
 * feature is not configured, and the harness decides nothing at all (see AutonomyGates).
 */
public record AutonomyConfiguration(List<AutonomyRule> gates) {
}
