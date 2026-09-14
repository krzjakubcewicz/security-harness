package com.example.securityharness.buildgate;

import com.example.securityharness.buildgate.BuildGateConfiguration.StackGate;
import com.example.securityharness.policy.Verdict;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs an ordered list of shell commands (e.g. compile, test) and reports whether the
 * build is green. Steps run through the OS shell so any language's tooling works from
 * a single command string. Each step's onFailure decides what its failure means for the
 * whole run: BLOCK/MANUAL_REVIEW stop the gate immediately, ALLOW just logs and continues.
 *
 * The gate does not decide what the service is - the workflow's stack step does that before
 * anything is remediated, and hands the answer here. Only the detected stacks' steps run. A
 * service matching no stack cannot be proven to build, so it is MANUAL_REVIEW rather than a
 * silent pass.
 */
public class BuildGate {
    private static final Logger log = LoggerFactory.getLogger(BuildGate.class);

    /** Empty when the gate was given stacks to detect instead of a fixed step list. */
    private final List<BuildGateStep> steps;

    /** Empty when the gate was given the steps outright - nothing to detect. */
    private final Map<String, StackGate> stacks;

    private final Path workingDirectory;

    public BuildGate(List<BuildGateStep> steps, Path workingDirectory) {
        this.steps = List.copyOf(steps);
        this.stacks = Map.of();
        this.workingDirectory = workingDirectory;
    }

    public BuildGate(Map<String, StackGate> stacks, Path workingDirectory) {
        this.steps = List.of();
        this.stacks = new LinkedHashMap<>(stacks);
        this.workingDirectory = workingDirectory;
    }

    /** {@code detected} is what the stack step found - empty when it found nothing. */
    public BuildGateResult evaluate(List<String> detected) {
        if (!stacks.isEmpty() && detected.isEmpty()) {
            log.warn("No project stack detected in {} - manual review", workingDirectory);
            return new BuildGateResult(Verdict.MANUAL_REVIEW, List.of(), List.of());
        }

        List<BuildGateResult.StepResult> results = new ArrayList<>();
        for (BuildGateStep step : stepsToRun(detected)) {
            int exitCode = run(step);
            results.add(new BuildGateResult.StepResult(step.name(), exitCode == 0, exitCode));
            if (exitCode != 0) {
                log.warn("Build gate step '{}' failed ({})", step.name(), step.onFailure());
                if (step.onFailure() != Verdict.ALLOW) {
                    return new BuildGateResult(step.onFailure(), detected, results);
                }
            }
        }
        return new BuildGateResult(Verdict.ALLOW, detected, results);
    }

    private List<BuildGateStep> stepsToRun(List<String> detected) {
        if (stacks.isEmpty()) {
            return steps;
        }
        List<BuildGateStep> toRun = new ArrayList<>();
        for (String name : detected) {
            StackGate stack = stacks.get(name);
            if (stack != null) {
                toRun.addAll(stack.steps());
            }
        }
        return toRun;
    }

    /** The step's exit code, or -1 when the command could not be run at all. */
    private int run(BuildGateStep step) {
        try {
            Process process = new ProcessBuilder(shellCommand(step.command()))
                    .directory(workingDirectory.toFile())
                    .redirectErrorStream(true)
                    .start();
            String output = new String(process.getInputStream().readAllBytes());
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                log.warn("  {} -> exit {}\n{}", step.name(), exitCode, output);
            }
            return exitCode;
        } catch (IOException e) {
            log.warn("  {} -> could not run: {}", step.name(), e.getMessage());
            return -1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("  {} -> interrupted", step.name());
            return -1;
        }
    }

    private static List<String> shellCommand(String command) {
        return System.getProperty("os.name", "").toLowerCase().contains("win")
                ? List.of("cmd.exe", "/c", command)
                : List.of("/bin/sh", "-c", command);
    }
}
