package com.example.securityharness;

import com.example.securityharness.autonomy.AutonomyActions;
import com.example.securityharness.autonomy.AutonomyConfiguration;
import com.example.securityharness.autonomy.AutonomyGates;
import com.example.securityharness.autonomy.LoggingAutonomyActions;
import com.example.securityharness.buildgate.BuildGate;
import com.example.securityharness.buildgate.BuildGateConfiguration.StackGate;
import com.example.securityharness.buildgate.BuildGateConfiguration;
import com.example.securityharness.config.ConfigLoadException;
import com.example.securityharness.config.ConfigLoader;
import com.example.securityharness.findings.Finding;
import com.example.securityharness.findings.FindingsReport;
import com.example.securityharness.guards.AgentGuards;
import com.example.securityharness.guards.GuardRule;
import com.example.securityharness.guards.GuardsConfiguration;
import com.example.securityharness.remediation.Context;
import com.example.securityharness.remediation.Remediator;
import com.example.securityharness.remediation.Outcome;
import com.example.securityharness.remediation.Workflow;
import com.example.securityharness.report.RunReport;
import com.example.securityharness.stack.StackDetector;
import com.example.securityharness.report.RunReportWriter;
import com.example.securityharness.verify.ChangeVerificationFailure;
import com.example.securityharness.verify.ChangeVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class SecurityHarnessApp {
    private static final Logger log = LoggerFactory.getLogger(SecurityHarnessApp.class.getName());

    /** Group key for findings whose service is missing from the report. */
    static final String UNKNOWN_SERVICE = "(unknown)";

    public static void main(String[] args) {
        String vulnerabilitiesPath = parseArg(args, "--vulnerabilities");
        if (vulnerabilitiesPath == null) {
            log.error("Usage: security-harness --vulnerabilities <path-to-findings.json>"
                    + " [--repos <repos-root>] [--no-verify-changes] [--output <report-dir>]"); //TODO: Make --repos mandatory
            System.exit(1);
            return;
        }
        String reposArg = parseArg(args, "--repos");
        Path reposRoot = Path.of(reposArg != null ? reposArg : System.getProperty("user.dir"));
        boolean verifyChanges = !hasFlag(args, "--no-verify-changes");
        String outputPath = parseArg(args, "--output");

        Instant startedAt = Instant.now();
        Map<String, Context> contexts = new LinkedHashMap<>();
        Map<String, Path> serviceDirectories = new LinkedHashMap<>();
        // Which service the run was on when it stopped. Null once the queue drains: a failure
        // after that belongs to the run, not to the last service that happened to succeed.
        String currentService = null;

        try {
            ConfigLoader yaml = ConfigLoader.yaml();
            List<GuardRule> guardRules = yaml.loadResource("/guards.yaml", GuardsConfiguration.class).guards();
            Map<String, StackGate> buildGateStacks = yaml.loadResource("/build-gate.yaml", BuildGateConfiguration.class).stacks();
            AutonomyGates autonomyGates = new AutonomyGates(
                    yaml.loadResource("/autonomy.yaml", AutonomyConfiguration.class).gates());
            AutonomyActions autonomyActions = new LoggingAutonomyActions();
            List<Finding> findings = ConfigLoader.json().load(Path.of(vulnerabilitiesPath), FindingsReport.class).findings();
            log.info("Loaded {} findings", findings.size());

            AgentGuards guards = new AgentGuards(guardRules);
            // Every configured stack's output, not the detected one's: the verifier is built before
            // the workflow has had a chance to say what this service is.
            List<String> buildOutput = buildGateStacks.values().stream()
                    .flatMap(stack -> stack.buildOutput().stream()).distinct().toList();

            for (Map.Entry<String, List<Finding>> group : groupByService(findings).entrySet()) {
                String service = group.getKey();
                currentService = service;
                Path serviceDirectory = reposRoot.resolve(service);
                Context context = new Context(group.getValue());
                // Filed before the run, not after, so an abort mid-service still reports it.
                contexts.put(service, context);
                serviceDirectories.put(service, serviceDirectory);
                if (Files.isDirectory(serviceDirectory)) {
                    log.info("--- {} ({} finding(s)) in {} ---", service, group.getValue().size(), serviceDirectory);
                    ChangeVerifier changeVerifier = null;
                    if (verifyChanges) {
                        changeVerifier = new ChangeVerifier(serviceDirectory, buildOutput);
                        changeVerifier.requireCleanTree();
                    }
                    new Workflow(
                            new Remediator(serviceDirectory, guards),
                            guards,
                            new BuildGate(buildGateStacks, serviceDirectory),
                            new StackDetector(buildGateStacks, serviceDirectory),
                            changeVerifier,
                            autonomyGates,
                            autonomyActions)
                            .run(context);
                } else {
                    log.error("No directory for service {} at {} - skipping", service, serviceDirectory);
                    context.finish(Outcome.NEEDS_ATTENTION);
                }
            }

            currentService = null;

            int exitCode = report(contexts);
            writeReport(outputPath, startedAt, vulnerabilitiesPath, reposRoot, exitCode, contexts,
                    serviceDirectories, null);
            if (exitCode != 0) {
                System.exit(exitCode);
            }
        } catch (RuntimeException e) {
            // Still ends the process the way it always has - it just leaves evidence behind first.
            log.error("Run aborted: {}", e.getMessage());
            markUnfinishedServices(contexts);
            writeReport(outputPath, startedAt, vulnerabilitiesPath, reposRoot, 1, contexts,
                    serviceDirectories, abortOf(e, currentService));
            if (e instanceof ChangeVerificationFailure) {
                // The harness cannot account for what it changed: the stack trace is the point.
                throw e;
            }
            System.exit(1);
        } catch (ConfigLoadException e) {
            log.error("Error: {}", e.getMessage());
            writeReport(outputPath, startedAt, vulnerabilitiesPath, reposRoot, 1, contexts,
                    serviceDirectories, abortOf(e, currentService));
            System.exit(1);
        }
    }

    /**
     * What stopped the run, as the report records it. The message, not the type, is the part worth
     * reading - it names the files the harness could not account for - so a failure with no message
     * falls back to toString rather than writing "null" into the report.
     */
    static RunReport.Abort abortOf(Throwable e, String service) {
        return new RunReport.Abort(e.getClass().getSimpleName(), service,
                e.getMessage() == null ? e.toString() : e.getMessage());
    }

    /**
     * Writes the run report when --output was given. A report that cannot be written is loud but
     * harmless: the run's own exit code says whether the findings were resolved, and that answer
     * must not change because a directory was not writable.
     */
    static void writeReport(String outputPath, Instant startedAt, String vulnerabilitiesPath, Path reposRoot,
                            int exitCode, Map<String, Context> contexts,
                            Map<String, Path> serviceDirectories, RunReport.Abort abort) {
        if (outputPath == null) {
            return;
        }
        try {
            new RunReportWriter().write(
                    RunReport.of(startedAt, Instant.now(), vulnerabilitiesPath, reposRoot, exitCode,
                            contexts, serviceDirectories, abort),
                    Path.of(outputPath));
        } catch (IOException | RuntimeException e) {
            // toString, not getMessage: a FileSystemException's message is just the path again.
            log.error("Could not write the run report to {}: {}", outputPath, e.toString());
        }
    }

    /** An aborted run leaves services mid-flight; the report should call those what they are. */
    private static void markUnfinishedServices(Map<String, Context> contexts) {
        for (Context context : contexts.values()) {
            if (context.getOutcome() == null) {
                context.finish(Outcome.NEEDS_ATTENTION);
            }
        }
    }

    /** Splits the findings into one queue per service, keeping the order they appear in the report. */
    static Map<String, List<Finding>> groupByService(List<Finding> findings) {
        return findings.stream().collect(Collectors.groupingBy(
                finding -> finding.service() == null ? UNKNOWN_SERVICE : finding.service(),
                LinkedHashMap::new,
                Collectors.toList()));
    }

    /** Prints the per-service summary and returns the process exit code. */
    static int report(Map<String, Context> contexts) {
        log.info("--- remediation summary ---");
        int unresolved = 0;
        boolean anyServiceNeedsAttention = false;

        for (Map.Entry<String, Context> entry : contexts.entrySet()) {
            Context context = entry.getValue();
            log.info("{}:", entry.getKey());
            for (Map.Entry<String, Outcome> outcome : context.getOutcomes().entrySet()) {
                log.info("  {}: {}", outcome.getKey(), outcome.getValue());
                if (outcome.getValue() != Outcome.SUCCESS) {
                    unresolved++;
                }
            }
            if (context.getOutcome() == Outcome.NEEDS_ATTENTION) {
                log.info("  ended in NEEDS_ATTENTION");
                anyServiceNeedsAttention = true;
            }
        }

        log.info("{} finding(s) need attention", unresolved);
        return anyServiceNeedsAttention || unresolved > 0 ? 1 : 0;
    }

    /** True when the flag is present at all. parseArg only reads flags that carry a value. */
    static boolean hasFlag(String[] args, String flag) {
        for (String arg : args) {
            if (flag.equals(arg)) {
                return true;
            }
        }
        return false;
    }

    static String parseArg(String[] args, String flag) {
        for (int i = 0; i < args.length; i++) {
            if (flag.equals(args[i])) {
                if (i + 1 >= args.length) {
                    return null;
                }
                return args[i + 1];
            }
        }
        return null;
    }
}
