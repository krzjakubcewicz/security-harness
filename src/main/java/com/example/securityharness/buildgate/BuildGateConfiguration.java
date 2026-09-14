package com.example.securityharness.buildgate;

import java.util.List;
import java.util.Map;

/**
 * The build gate config: one entry per stack the harness knows how to build. A stack applies
 * to a service only when its marker file sits in the service directory, so a Python service
 * never runs Maven and vice versa. Map order is YAML order, which is the order the steps of
 * matched stacks run in.
 */
public record BuildGateConfiguration(Map<String, StackGate> stacks) {


    public record StackGate(String marker, String dependencyFile, List<BuildGateStep> steps,
                            List<String> buildOutput) {

        /** A stack the harness builds but never rewrites - no dependency file to name. */
        public StackGate(String marker, List<BuildGateStep> steps) {
            this(marker, null, steps, List.of());
        }

        public StackGate(String marker, String dependencyFile, List<BuildGateStep> steps) {
            this(marker, dependencyFile, steps, List.of());
        }

        public StackGate {
            if (marker == null || marker.isBlank()) {
                throw new IllegalArgumentException("Build gate stack is missing a marker file");
            }
            steps = List.copyOf(steps);
            buildOutput = buildOutput == null ? List.of() : List.copyOf(buildOutput);
        }
    }
}
