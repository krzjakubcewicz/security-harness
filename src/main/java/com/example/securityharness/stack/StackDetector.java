package com.example.securityharness.stack;

import com.example.securityharness.buildgate.BuildGateConfiguration.StackGate;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class StackDetector {

    /** Detects nothing. For the workflows that were never given stacks - tests, the no-config path. */
    public static StackDetector none() {
        return new StackDetector(Map.of(), Path.of("."));
    }

    private final Map<String, StackGate> stacks;
    private final Path serviceDirectory;

    public StackDetector(Map<String, StackGate> stacks, Path serviceDirectory) {
        this.stacks = new LinkedHashMap<>(stacks);
        this.serviceDirectory = serviceDirectory;
    }

    /** False when no stacks were configured: there is nothing to detect and nothing to gate on. */
    public boolean isConfigured() {
        return !stacks.isEmpty();
    }

    /**
     * Every configured stack whose marker file sits at the top of the service directory, in
     * config order. A service can be more than one thing, and a polyglot repo has to build as
     * both, so this is a list rather than a single answer.
     */
    public List<String> detect() {
        List<String> detected = new ArrayList<>();
        for (Map.Entry<String, StackGate> stack : stacks.entrySet()) {
            if (Files.exists(serviceDirectory.resolve(stack.getValue().marker()))) {
                detected.add(stack.getKey());
            }
        }
        return List.copyOf(detected);
    }

    /**
     * The file the detected stack declares its dependency versions in, or null when that is not
     * one stack's answer to give: nothing detected, two stacks detected - each with its own file,
     * and the stack alone cannot say which one a package is declared in - or a stack the harness
     * only builds. Callers fall back to whatever they did before detection existed.
     */
    public String dependencyFile(List<String> detected) {
        if (detected.size() != 1) {
            return null;
        }
        StackGate stack = stacks.get(detected.getFirst());
        return stack == null ? null : stack.dependencyFile();
    }

    /** The directory these answers are about - what a log line should name. */
    public Path serviceDirectory() {
        return serviceDirectory;
    }

    /** What detection looked for, so a run that found nothing can say what it expected. */
    public List<String> markerNames() {
        return stacks.values().stream().map(StackGate::marker).toList();
    }
}
