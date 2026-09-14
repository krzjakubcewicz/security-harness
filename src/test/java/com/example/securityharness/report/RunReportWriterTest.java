package com.example.securityharness.report;

import com.example.securityharness.autonomy.AutonomyAction;
import com.example.securityharness.autonomy.AutonomyDecision;
import com.example.securityharness.buildgate.BuildGateResult;
import com.example.securityharness.findings.Finding;
import com.example.securityharness.findings.Severity;
import com.example.securityharness.guards.GuardRule;
import com.example.securityharness.policy.Verdict;
import com.example.securityharness.remediation.Context;
import com.example.securityharness.remediation.Outcome;
import com.example.securityharness.remediation.Strategy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RunReportWriterTest {

    private static final Instant STARTED = Instant.parse("2026-09-13T10:00:00Z");
    private static final Instant FINISHED = Instant.parse("2026-09-13T10:00:07Z");

    private static Finding finding(String id, String cve, String packageName, String fixedVersion) {
        return new Finding(id, cve, Severity.HIGH, "inventory-api",
                packageName, "1.30", "transitive", fixedVersion, 4, "n/a");
    }

    /** One service that remediated F-1 through the agent and held F-2 back for a human. */
    private static Context inventoryApi() {
        Context context = new Context(List.of(
                finding("F-1", "CVE-2022-1471", "org.yaml:snakeyaml", null),
                finding("F-2", "CVE-2015-6420", "commons-collections:commons-collections", null)));

        context.setStrategy(Strategy.AGENT_REMEDIATION);
        context.startAttempts();
        context.recordGuardDecision(GuardRule.When.BEFORE, null, Verdict.ALLOW);
        context.addFileChanged("pom.xml");
        context.setVerified(true);
        context.recordOutcome(Outcome.SUCCESS);

        context.setStrategy(Strategy.AGENT_REMEDIATION);
        context.startAttempts();
        context.recordGuardDecision(GuardRule.When.AFTER, "distrust-flaky", Verdict.MANUAL_REVIEW);
        context.setVerified(true);
        context.recordOutcome(Outcome.NEEDS_ATTENTION);

        context.setBuildGate(new BuildGateResult(Verdict.ALLOW, List.of("java"),
                List.of(new BuildGateResult.StepResult("compile", true, 0))));
        context.finish(Outcome.SUCCESS);
        return context;
    }

    private static RunReport report() {
        Map<String, Context> contexts = new LinkedHashMap<>();
        contexts.put("inventory-api", inventoryApi());
        Map<String, Path> directories = new LinkedHashMap<>();
        directories.put("inventory-api", Path.of("repos", "inventory-api"));

        return RunReport.of(STARTED, FINISHED, "examples/findings-agent.json",
                Path.of("repos"), 1, contexts, directories, null);
    }

    @Test
    void theRunBlockCarriesWhatWasAskedAndHowItEnded() {
        RunReport.Run run = report().run();

        assertEquals("2026-09-13T10:00:00Z", run.startedAt());
        assertEquals("2026-09-13T10:00:07Z", run.finishedAt());
        assertEquals("examples/findings-agent.json", run.vulnerabilitiesFile());
        assertEquals("repos", run.reposRoot());
        assertEquals(1, run.exitCode());
    }

    @Test
    void anAbortedRunSaysWhatStoppedIt() {
        RunReport report = RunReport.of(STARTED, FINISHED, "f.json", Path.of("repos"), 1,
                Map.of(), Map.of(),
                new RunReport.Abort("ChangeVerificationFailure", "inventory-api",
                        "Files changed on disk do not match what the agent declared."
                                + "\n  changed but not declared: [smuggled.txt]"));

        String json = new RunReportWriter().toJson(report);

        assertTrue(json.contains("\"type\" : \"ChangeVerificationFailure\""), json);
        assertTrue(json.contains("\"service\" : \"inventory-api\""), json);
        assertTrue(json.contains("smuggled.txt"), json);
    }

    @Test
    void aRunThatFinishedOnItsOwnTermsHasNoAbort() {
        RunReport report = RunReport.of(STARTED, FINISHED, "f.json", Path.of("repos"), 0,
                Map.of(), Map.of(), null);

        assertNull(report.run().abort());
    }

    @Test
    void theSummaryCountsEveryFindingByHowItEnded() {
        RunReport.Summary summary = report().summary();

        assertEquals(2, summary.total());
        assertEquals(1, summary.success());
        assertEquals(1, summary.needsAttention());
        assertEquals(0, summary.notProcessed());
    }

    @Test
    void findingsAServiceNeverReachedAreCountedAsNotProcessed() {
        Context skipped = new Context(List.of(
                finding("F-9", "CVE-0000-0000", "example:example", "2.0")));
        skipped.finish(Outcome.NEEDS_ATTENTION);
        Map<String, Context> contexts = new LinkedHashMap<>();
        contexts.put("report-worker", skipped);

        RunReport.Summary summary = RunReport.of(STARTED, FINISHED, "f.json", Path.of("repos"), 1,
                contexts, Map.of(), null).summary();

        assertEquals(1, summary.total());
        assertEquals(1, summary.notProcessed());
        assertEquals(0, summary.needsAttention(),
                "a finding that never ran is not a remediation that needs attention");
    }

    @Test
    void aServiceWithNoResolvedDirectoryReportsANullOne() {
        RunReport.Service service = RunReport.of(STARTED, FINISHED, "f.json", Path.of("repos"), 0,
                Map.of("report-worker", new Context(List.of())), Map.of(), null).services().get(0);

        assertNull(service.directory());
        assertNull(service.buildGate(), "a service that never reached the gate has no gate result");
    }

    @Test
    void theJsonCarriesThePerFindingTraceUnderTheServiceThatProducedIt() {
        String json = new RunReportWriter().toJson(report());

        assertTrue(json.contains("\"service\" : \"inventory-api\""), json);
        assertTrue(json.contains("\"strategy\" : \"AGENT_REMEDIATION\""), json);
        assertTrue(json.contains("\"attempts\" : 1"), json);
        assertTrue(json.contains("\"verified\" : true"), json);
        assertTrue(json.contains("\"filesChanged\" : [ \"pom.xml\" ]"), json);
        assertTrue(json.contains("\"rule\" : \"distrust-flaky\""), json);
        assertTrue(json.contains("\"outcome\" : \"NEEDS_ATTENTION\""), json);
        assertTrue(json.contains("\"exitCode\" : 0"), "expected the build gate step's exit code. " + json);
        // A null fixedVersion is what routed F-1 to the agent, so it has to survive into the report.
        assertTrue(json.contains("\"fixedVersion\" : null"), json);
    }

    @Test
    void theReportCarriesWhatTheAutonomyGateDecided() {
        Context context = new Context(List.of(
                finding("F-1", "CVE-2022-1471", "org.yaml:snakeyaml", "2.0")));
        context.setAutonomy(new AutonomyDecision("escalate-major-version-changes",
                AutonomyAction.JIRA, "F-1", "F-1 org.yaml:snakeyaml 1.30 -> 2.0 (MAJOR, DEPENDENCY_FILE_ONLY)"));
        context.finish(Outcome.SUCCESS);

        String json = new RunReportWriter().toJson(RunReport.of(STARTED, FINISHED, "f.json",
                Path.of("repos"), 0, Map.of("inventory-api", context), Map.of(), null));

        assertTrue(json.contains("\"action\" : \"JIRA\""), json);
        assertTrue(json.contains("\"rule\" : \"escalate-major-version-changes\""), json);
        assertTrue(json.contains("MAJOR, DEPENDENCY_FILE_ONLY"), json);
    }

    @Test
    void theReportCarriesWhatTheAgentDidToTheTests() {
        Context context = new Context(List.of(
                finding("F-1", "CVE-2022-1471", "org.yaml:snakeyaml", "2.0")));
        context.setStrategy(Strategy.AGENT_REMEDIATION);
        context.startAttempts();
        context.setTestCounts(15, 12);
        context.recordOutcome(Outcome.NEEDS_ATTENTION);
        context.setAutonomy(new AutonomyDecision("a-finding-a-human-must-read",
                AutonomyAction.PULL_REQUEST, "F-1",
                "F-1 org.yaml:snakeyaml 1.30 -> 2.0 (MAJOR, SOURCE_CODE)",
                "TESTS LOST: F-1 left 12 tests that will run where there were 15"));
        context.finish(Outcome.SUCCESS);

        String json = new RunReportWriter().toJson(RunReport.of(STARTED, FINISHED, "f.json",
                Path.of("repos"), 0, Map.of("inventory-api", context), Map.of(), null));

        // The numbers a pipeline reads, and the sentence it puts on the pull request.
        assertTrue(json.contains("\"testsBefore\" : 15"), json);
        assertTrue(json.contains("\"testsAfter\" : 12"), json);
        assertTrue(json.contains("TESTS LOST: F-1 left 12 tests"), json);
    }

    @Test
    void anOrdinaryFindingReportsNoTestCounts() {
        Context context = new Context(List.of(
                finding("F-1", "CVE-2022-1471", "org.yaml:snakeyaml", "2.0")));
        context.setStrategy(Strategy.DEPENDENCY_UPDATE);
        context.startAttempts();
        context.recordOutcome(Outcome.SUCCESS);
        context.finish(Outcome.SUCCESS);

        String json = new RunReportWriter().toJson(RunReport.of(STARTED, FINISHED, "f.json",
                Path.of("repos"), 0, Map.of("inventory-api", context), Map.of(), null));

        assertTrue(json.contains("\"testsBefore\" : null"), json);
        assertTrue(json.contains("\"testsAfter\" : null"), json);
    }

    @Test
    void theReportLandsInADirectoryThatDidNotExistYet(@TempDir Path tempDir) throws IOException {
        Path outputDirectory = tempDir.resolve("reports").resolve("nested");

        Path written = new RunReportWriter().write(report(), outputDirectory);

        assertTrue(Files.isRegularFile(written), "expected " + written + " to exist");
        assertEquals(outputDirectory, written.getParent());
        assertTrue(written.getFileName().toString().matches("run-\\d{8}T\\d{6}Z\\.json"),
                "unexpected report file name: " + written.getFileName());
        assertTrue(Files.readString(written, StandardCharsets.UTF_8).contains("\"id\" : \"F-1\""));
    }

    @Test
    void anExistingReportIsNeverOverwritten(@TempDir Path tempDir) throws IOException {
        Path existing = tempDir.resolve("run-20200101T000000Z.json");
        Files.writeString(existing, "{}", StandardCharsets.UTF_8);

        new RunReportWriter().write(report(), tempDir);

        assertEquals("{}", Files.readString(existing, StandardCharsets.UTF_8));
        try (var entries = Files.list(tempDir)) {
            assertEquals(2, entries.count(), "the new report must sit alongside the old one");
        }
    }
}
