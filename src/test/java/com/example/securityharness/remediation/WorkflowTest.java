package com.example.securityharness.remediation;

import com.example.securityharness.agent.LlmResponse;
import com.example.securityharness.agent.ToolCall;
import com.example.securityharness.autonomy.AutonomyAction;
import com.example.securityharness.autonomy.AutonomyActions;
import com.example.securityharness.autonomy.AutonomyDecision;
import com.example.securityharness.autonomy.AutonomyGates;
import com.example.securityharness.autonomy.AutonomyRule;
import com.example.securityharness.buildgate.BuildGate;
import com.example.securityharness.buildgate.BuildGateConfiguration.StackGate;
import com.example.securityharness.buildgate.BuildGateResult;
import com.example.securityharness.buildgate.BuildGateStep;
import com.example.securityharness.findings.Finding;
import com.example.securityharness.findings.Severity;
import com.example.securityharness.guards.AgentGuards;
import com.example.securityharness.guards.GuardDecision;
import com.example.securityharness.guards.GuardRule;
import com.example.securityharness.guards.GuardViolation;
import com.example.securityharness.policy.Verdict;
import com.example.securityharness.stack.StackDetector;
import com.example.securityharness.verify.ChangeVerificationFailure;
import com.example.securityharness.verify.ChangeVerifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class WorkflowTest {

    /** A direct dependency, so it takes the DEPENDENCY_UPDATE path whatever fixedVersion says. */
    static Finding finding(String id, String fixedVersion) {
        return new Finding(id, "CVE-0000-0000", Severity.HIGH, "inventory-api",
                "example:example", "1.0", "direct", fixedVersion, 1, "n/a");
    }

    /** What routes a finding is its path: anything but "direct" goes to the agent. */
    static Finding agentFinding(String id) {
        return agentFinding(id, "CVE-0000-0000", "example:example");
    }

    /** Records which operations ran and returns a scripted verify result. */
    static class StubRemediator extends Remediator {
        final List<String> calls = new ArrayList<>();
        boolean verifyResult = true;

        /** When set, every remediation this stub performs claims to have written this path. */
        String writes;

        private final Set<Path> written = new LinkedHashSet<>();

        @Override
        public void applyDependencyUpdate(Finding finding) {
            calls.add("update:" + finding.id());
            claimWrite();
        }

        @Override
        public LlmResponse invokeAgent(Finding finding, int attempt) {
            calls.add("agent:" + finding.id() + ":" + attempt);
            claimWrite();
            return new LlmResponse(List.of());
        }

        @Override
        public boolean verify(Finding finding, Strategy strategy) {
            calls.add("verify:" + finding.id());
            return verifyResult;
        }

        @Override
        public Set<Path> filesWritten() {
            return Set.copyOf(written);
        }

        private void claimWrite() {
            if (writes != null) {
                written.add(Path.of(writes));
            }
        }
    }

    @Test
    void aDirectDependencySucceedsViaDependencyUpdate() {
        StubRemediator remediator = new StubRemediator();
        Context context = new Context(List.of(finding("F-1", "1.1")));

        Outcome finalState = new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(Outcome.SUCCESS, finalState);
        assertEquals(Map.of("F-1", Outcome.SUCCESS), context.getOutcomes());
        assertEquals(List.of("update:F-1", "verify:F-1"), remediator.calls);
    }

    @Test
    void aDirectDependencyWithNoFixedVersionGoesStraightToNeedsAttention() {
        // There is no version to upgrade to, so the update would be a no-op and every retry an
        // identical one. Nothing is attempted and no attempt is spent.
        StubRemediator remediator = new StubRemediator();
        Context context = new Context(List.of(finding("F-1", null)));

        Outcome finalState = new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(Outcome.SUCCESS, finalState, "one finding for a human does not fail the run");
        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION), context.getOutcomes());
        assertEquals(List.of(), remediator.calls, "neither the update nor verification should run");
    }

    @Test
    void aTransitiveDependencyRoutesToTheAgent() {
        StubRemediator remediator = new StubRemediator();
        Context context = new Context(List.of(agentFinding("F-2")));

        new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(List.of("agent:F-2:1", "verify:F-2"), remediator.calls);
    }

    @Test
    void emptyFindingsListReachesSuccessImmediately() {
        StubRemediator remediator = new StubRemediator();
        Context context = new Context(List.of());

        assertEquals(Outcome.SUCCESS, new Workflow(remediator, new AgentGuards()).run(context));
        assertEquals(List.of(), remediator.calls);
    }

    @Test
    void findingsAreProcessedInOrder() {
        StubRemediator remediator = new StubRemediator();
        Context context = new Context(
                List.of(finding("F-1", "1.1"), finding("F-2", "2.0")));

        new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(List.of("update:F-1", "verify:F-1", "update:F-2", "verify:F-2"), remediator.calls);
        assertEquals(List.of("F-1", "F-2"), List.copyOf(context.getOutcomes().keySet()));
    }

    @Test
    void failingVerificationRetriesUpToMaxAttemptsThenNeedsAttention() {
        StubRemediator remediator = new StubRemediator();
        remediator.verifyResult = false;
        Context context = new Context(List.of(finding("F-1", "1.1")), 3);

        Outcome finalState = new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(Outcome.SUCCESS, finalState);
        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION), context.getOutcomes());
        assertEquals(List.of(
                "update:F-1", "verify:F-1",
                "update:F-1", "verify:F-1",
                "update:F-1", "verify:F-1"), remediator.calls);
    }

    @Test
    void maxAttemptsOfOneMeansNoRetry() {
        StubRemediator remediator = new StubRemediator();
        remediator.verifyResult = false;
        Context context = new Context(List.of(finding("F-1", "1.1")), 1);

        new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(List.of("update:F-1", "verify:F-1"), remediator.calls);
        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION), context.getOutcomes());
    }

    @Test
    void agentRetriesCarryTheAttemptNumber() {
        StubRemediator remediator = new StubRemediator();
        remediator.verifyResult = false;
        Context context = new Context(List.of(agentFinding("F-2")), 3);

        new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(List.of(
                "agent:F-2:1", "verify:F-2",
                "agent:F-2:2", "verify:F-2",
                "agent:F-2:3", "verify:F-2"), remediator.calls);
    }

    @Test
    void oneFindingNeedingAttentionDoesNotStopTheRun() {
        StubRemediator remediator = new StubRemediator() {
            @Override
            public boolean verify(Finding finding, Strategy strategy) {
                calls.add("verify:" + finding.id());
                return !finding.id().equals("F-1");
            }
        };
        Context context = new Context(
                List.of(finding("F-1", "1.1"), finding("F-2", "2.0")), 2);

        Outcome finalState = new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(Outcome.SUCCESS, finalState);
        assertEquals(Outcome.NEEDS_ATTENTION, context.getOutcomes().get("F-1"));
        assertEquals(Outcome.SUCCESS, context.getOutcomes().get("F-2"));
    }

    @Test
    void attemptCounterResetsForTheNextFinding() {
        StubRemediator remediator = new StubRemediator() {
            @Override
            public boolean verify(Finding finding, Strategy strategy) {
                calls.add("verify:" + finding.id());
                return !finding.id().equals("F-1");
            }
        };
        Context context = new Context(
                List.of(finding("F-1", "1.1"), finding("F-2", "2.0")), 2);

        new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(List.of(
                "update:F-1", "verify:F-1",
                "update:F-1", "verify:F-1",
                "update:F-2", "verify:F-2"), remediator.calls);
    }

    @Test
    void unexpectedErrorEndsTheRunNeedingAttention() {
        StubRemediator remediator = new StubRemediator() {
            @Override
            public void applyDependencyUpdate(Finding finding) {
                throw new IllegalStateException("boom");
            }
        };
        Context context = new Context(List.of(finding("F-1", "1.1")));

        Outcome finalState = new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(Outcome.NEEDS_ATTENTION, finalState);
        assertEquals(Map.of(), context.getOutcomes());
    }

    private static GuardRule blockRule(GuardRule.When when) {
        return new GuardRule("test-block", when, Map.of(), Verdict.BLOCK);
    }

    private static GuardRule manualReviewRule(GuardRule.When when) {
        return new GuardRule("test-manual-review", when, Map.of(), Verdict.MANUAL_REVIEW);
    }

    @Test
    void beforeHookBlockSkipsAgentAndRecordsNeedsAttentionButRunContinues() {
        StubRemediator remediator = new StubRemediator();
        AgentGuards guards = new AgentGuards(List.of(blockRule(GuardRule.When.BEFORE)));
        Context context = new Context(
                List.of(agentFinding("F-1"), finding("F-2", "2.0")));

        Outcome finalState = new Workflow(remediator, guards).run(context);

        assertEquals(Outcome.SUCCESS, finalState);
        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION, "F-2", Outcome.SUCCESS), context.getOutcomes());
        assertEquals(List.of("update:F-2", "verify:F-2"), remediator.calls);
    }

    @Test
    void beforeHookManualReviewSkipsAgentAndVerify() {
        StubRemediator remediator = new StubRemediator();
        AgentGuards guards = new AgentGuards(List.of(manualReviewRule(GuardRule.When.BEFORE)));
        Context context = new Context(List.of(agentFinding("F-1")));

        new Workflow(remediator, guards).run(context);

        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION), context.getOutcomes());
        assertEquals(List.of(), remediator.calls);
    }

    @Test
    void beforeHookAllowsWhenNoRuleMatches() {
        StubRemediator remediator = new StubRemediator();
        AgentGuards guards = new AgentGuards(List.of(
                new GuardRule("non-matching", GuardRule.When.BEFORE, Map.of("severity", "LOW"), Verdict.BLOCK)));
        Context context = new Context(List.of(agentFinding("F-1")));

        new Workflow(remediator, guards).run(context);

        assertEquals(List.of("agent:F-1:1", "verify:F-1"), remediator.calls);
    }

    @Test
    void beforeHookDoesNotApplyToDependencyUpdateStrategy() {
        StubRemediator remediator = new StubRemediator();
        AgentGuards guards = new AgentGuards(List.of(blockRule(GuardRule.When.BEFORE)));
        Context context = new Context(List.of(finding("F-1", "1.1")));

        Outcome finalState = new Workflow(remediator, guards).run(context);

        assertEquals(Outcome.SUCCESS, finalState);
        assertEquals(Map.of("F-1", Outcome.SUCCESS), context.getOutcomes());
        assertEquals(List.of("update:F-1", "verify:F-1"), remediator.calls);
    }

    @Test
    void afterHookBlockOverridesClaimedSuccess() {
        StubRemediator remediator = new StubRemediator();
        AgentGuards guards = new AgentGuards(List.of(blockRule(GuardRule.When.AFTER)));
        Context context = new Context(List.of(agentFinding("F-1")));

        new Workflow(remediator, guards).run(context);

        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION), context.getOutcomes());
    }

    @Test
    void afterHookManualReviewOverridesClaimedSuccess() {
        StubRemediator remediator = new StubRemediator();
        AgentGuards guards = new AgentGuards(List.of(manualReviewRule(GuardRule.When.AFTER)));
        Context context = new Context(List.of(agentFinding("F-1")));

        new Workflow(remediator, guards).run(context);

        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION), context.getOutcomes());
    }

    @Test
    void afterHookNotConsultedWhenVerifyFails() {
        StubRemediator remediator = new StubRemediator();
        remediator.verifyResult = false;
        AgentGuards guards = new AgentGuards(List.of(blockRule(GuardRule.When.AFTER)));
        Context context = new Context(List.of(agentFinding("F-1")), 1);

        new Workflow(remediator, guards).run(context);

        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION), context.getOutcomes());
        assertFalse(remediator.calls.isEmpty());
    }

    @Test
    void afterHookDoesNotApplyToDependencyUpdateStrategy() {
        StubRemediator remediator = new StubRemediator();
        AgentGuards guards = new AgentGuards(List.of(blockRule(GuardRule.When.AFTER)));
        Context context = new Context(List.of(finding("F-1", "1.1")));

        new Workflow(remediator, guards).run(context);

        assertEquals(Map.of("F-1", Outcome.SUCCESS), context.getOutcomes());
    }

    /** Stands in for a Remediator whose tool-call screening refused a write. */
    private static StubRemediator remediatorViolating(Verdict action) {
        return new StubRemediator() {
            @Override
            public LlmResponse invokeAgent(Finding finding, int attempt) {
                calls.add("agent:" + finding.id() + ":" + attempt);
                throw new GuardViolation("protect-version-control", action,
                        new com.example.securityharness.agent.ToolCall("writeFile", ".git/config", "body"));
            }
        };
    }

    @Test
    void toolGuardBlockRecordsNeedsAttentionForThatFindingAndTheRunContinues() {
        StubRemediator remediator = remediatorViolating(Verdict.BLOCK);
        Context context = new Context(
                List.of(agentFinding("F-1"), finding("F-2", "2.0")));

        Outcome finalState = new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(Outcome.SUCCESS, finalState);
        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION, "F-2", Outcome.SUCCESS), context.getOutcomes());
        assertEquals(List.of("agent:F-1:1", "update:F-2", "verify:F-2"), remediator.calls);
    }

    @Test
    void toolGuardManualReviewRecordsNeedsAttentionAndSkipsVerify() {
        StubRemediator remediator = remediatorViolating(Verdict.MANUAL_REVIEW);
        Context context = new Context(List.of(agentFinding("F-1")));

        Outcome finalState = new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(Outcome.SUCCESS, finalState);
        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION), context.getOutcomes());
        assertEquals(List.of("agent:F-1:1"), remediator.calls);
    }

    private static BuildGateStep gateStep(String command, Verdict onFailure) {
        return new BuildGateStep("test-step", command, onFailure);
    }

    @Test
    void buildGateAllowingResultsInWholeRunSuccess(@TempDir Path tempDir) {
        StubRemediator remediator = new StubRemediator();
        BuildGate buildGate = new BuildGate(List.of(gateStep("exit 0", Verdict.BLOCK)), tempDir);
        Context context = new Context(List.of(finding("F-1", "1.1")));

        Outcome finalState = new Workflow(remediator, new AgentGuards(), buildGate).run(context);

        assertEquals(Outcome.SUCCESS, finalState);
        assertEquals(Map.of("F-1", Outcome.SUCCESS), context.getOutcomes());
    }

    @Test
    void buildGateBlockingSendsTheWholeRunToNeedsAttentionEvenThoughEveryFindingSucceeded() {
        StubRemediator remediator = new StubRemediator();
        BuildGate buildGate = new BuildGate(List.of(gateStep("exit 1", Verdict.BLOCK)), Path.of("."));
        Context context = new Context(List.of(finding("F-1", "1.1")));

        Outcome finalState = new Workflow(remediator, new AgentGuards(), buildGate).run(context);

        assertEquals(Outcome.NEEDS_ATTENTION, finalState);
        assertEquals(Map.of("F-1", Outcome.SUCCESS), context.getOutcomes());
    }

    @Test
    void buildGateManualReviewEndsTheWholeRunInNeedsAttention() {
        StubRemediator remediator = new StubRemediator();
        BuildGate buildGate = new BuildGate(List.of(gateStep("exit 1", Verdict.MANUAL_REVIEW)), Path.of("."));
        Context context = new Context(List.of(finding("F-1", "1.1")));

        Outcome finalState = new Workflow(remediator, new AgentGuards(), buildGate).run(context);

        assertEquals(Outcome.NEEDS_ATTENTION, finalState);
        assertEquals(Map.of("F-1", Outcome.SUCCESS), context.getOutcomes());
    }

    /**
     * Every other RuntimeException becomes a run that needs attention. This one must not: it says the harness
     * cannot account for what it changed, which is a fact about the harness, not about a finding.
     */
    @Test
    void aChangeVerificationFailureIsNotSwallowedIntoARunOutcome(@TempDir Path tempDir) throws Exception {
        gitInit(tempDir);
        StubRemediator remediator = new StubRemediator();
        // The stub declares nothing, and nothing was written, so the verifier passing here would
        // mean it never ran. An unaccounted-for file makes it disagree.
        Files.writeString(tempDir.resolve("smuggled.txt"), "written outside the toolbox", StandardCharsets.UTF_8);
        ChangeVerifier verifier = new ChangeVerifier(tempDir);
        Context context = new Context(List.of(finding("F-1", "1.1")));

        ChangeVerificationFailure failure = assertThrows(ChangeVerificationFailure.class,
                () -> new Workflow(remediator, new AgentGuards(),
                        new BuildGate(List.of(), tempDir), verifier).run(context));

        assertTrue(failure.getMessage().contains("smuggled.txt"), failure.getMessage());
        assertNull(context.getOutcome(),
                "the run must not have been quietly closed with an outcome of its own");
    }

    /** A finding the agent handles: its path is not "direct", which is what routes it. */
    static Finding agentFinding(String id, String cve, String packageName) {
        return new Finding(id, cve, Severity.HIGH, "inventory-api",
                packageName, "1.30", "transitive via spring-boot-starter", null, 4, "n/a");
    }

    @Test
    void theRunTraceKeepsTheStrategyAttemptsAndGuardVerdictsForEachFinding() {
        StubRemediator remediator = new StubRemediator();
        AgentGuards guards = new AgentGuards(List.of(manualReviewRule(GuardRule.When.AFTER)));
        Context context = new Context(
                List.of(agentFinding("F-1", "CVE-2022-1471", "org.yaml:snakeyaml")));

        new Workflow(remediator, guards).run(context);

        FindingRecord record = context.getRecords().get(0);
        assertEquals("F-1", record.id());
        assertEquals("CVE-2022-1471", record.cve());
        assertEquals("org.yaml:snakeyaml", record.packageName());
        assertEquals(Strategy.AGENT_REMEDIATION, record.strategy());
        assertEquals(1, record.attempts());
        assertTrue(record.verified());
        assertEquals(Outcome.NEEDS_ATTENTION, record.outcome());
        assertEquals(List.of(
                        new GuardDecision(GuardRule.When.BEFORE, null, Verdict.ALLOW),
                        new GuardDecision(GuardRule.When.AFTER, "test-manual-review", Verdict.MANUAL_REVIEW)),
                record.guardDecisions());
    }

    @Test
    void theRunTraceCountsEveryAttemptARetryingFindingTook() {
        StubRemediator remediator = new StubRemediator();
        remediator.verifyResult = false;
        Context context = new Context(
                List.of(agentFinding("F-1", "CVE-2022-1471", "org.yaml:snakeyaml")), 3);

        new Workflow(remediator, new AgentGuards()).run(context);

        FindingRecord record = context.getRecords().get(0);
        assertEquals(3, record.attempts());
        assertFalse(record.verified());
        assertEquals(Outcome.NEEDS_ATTENTION, record.outcome());
    }

    @Test
    void theRunTraceNamesTheToolRuleThatRefusedAWrite() {
        StubRemediator remediator = remediatorViolating(Verdict.MANUAL_REVIEW);
        Context context = new Context(
                List.of(agentFinding("F-1", "CVE-2022-1471", "org.yaml:snakeyaml")));

        new Workflow(remediator, new AgentGuards()).run(context);

        assertEquals(new GuardDecision(GuardRule.When.TOOL, "protect-version-control", Verdict.MANUAL_REVIEW),
                context.getRecords().get(0).guardDecisions().get(1));
    }

    /** What the agent actually wrote, named the way a report reader expects to see it. */
    @Test
    void theRunTraceListsWrittenFilesRelativeToTheServiceDirectory(@TempDir Path serviceDirectory) {
        Context context = new Context(
                List.of(agentFinding("F-40218", "CVE-2022-1471", "org.yaml:snakeyaml")));

        new Workflow(new Remediator(serviceDirectory), new AgentGuards(),
                new BuildGate(List.of(), serviceDirectory)).run(context);

        FindingRecord record = context.getRecords().get(0);
        assertEquals(List.of("pom.xml"), record.filesChanged());
        assertTrue(record.verified(), "the agent's own write is what verification reads back");
    }

    @Test
    void theBuildGateResultIsKeptForTheReport(@TempDir Path tempDir) {
        StubRemediator remediator = new StubRemediator();
        BuildGate buildGate = new BuildGate(List.of(gateStep("exit 0", Verdict.BLOCK)), tempDir);
        Context context = new Context(List.of(finding("F-1", "1.1")));

        new Workflow(remediator, new AgentGuards(), buildGate).run(context);

        assertEquals(Verdict.ALLOW, context.getBuildGate().action());
        assertEquals(List.of("test-step"),
                context.getBuildGate().steps().stream().map(BuildGateResult.StepResult::name).toList());
    }

    /** Git is not guaranteed on a build machine; skip rather than fail there. */
    private static void gitInit(Path directory) throws Exception {
        Process version = new ProcessBuilder("git", "--version").start();
        version.getInputStream().readAllBytes();
        assumeTrue(version.waitFor() == 0, "git is not usable here");

        Process init = new ProcessBuilder("git", "init", "-q")
                .directory(directory.toFile())
                .redirectErrorStream(true)
                .start();
        String output = new String(init.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assumeTrue(init.waitFor() == 0, "test setup: git init failed: " + output);
    }

    /** A detector over one stack whose marker is created, or not, by the test itself. */
    static StackDetector javaDetector(Path serviceDirectory) {
        return new StackDetector(Map.of("java",
                new StackGate("pom.xml", "pom.xml",
                        List.of(new BuildGateStep("compile", "exit 0", Verdict.BLOCK)))),
                serviceDirectory);
    }

    /** A gate with no steps and no stacks, so a test can isolate the stack step. */
    static BuildGate noGate(Path serviceDirectory) {
        return new BuildGate(List.of(), serviceDirectory);
    }

    @Test
    void theStackIsDeterminedBeforeAnyFindingIsProcessed(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);
        StubRemediator remediator = new StubRemediator();
        Context context = new Context(List.of(finding("F-1", "1.1")));

        new Workflow(remediator, new AgentGuards(), noGate(tempDir), javaDetector(tempDir), null)
                .run(context);

        assertEquals(List.of("java"), context.getStacks());
        assertEquals(List.of("update:F-1", "verify:F-1"), remediator.calls,
                "detection must not disturb the findings that follow it");
    }

    @Test
    void theDetectedStacksDependencyFileIsHandedToTheRemediator(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);
        List<String> told = new ArrayList<>();
        StubRemediator remediator = new StubRemediator() {
            @Override
            public void setStackDependencyFile(String stackDependencyFile) {
                told.add(stackDependencyFile);
                super.setStackDependencyFile(stackDependencyFile);
            }
        };

        new Workflow(remediator, new AgentGuards(), noGate(tempDir), javaDetector(tempDir), null)
                .run(new Context(List.of(finding("F-1", "1.1"))));

        assertEquals(List.of("pom.xml"), told, "told once, before the first finding");
    }

    @Test
    void anUndetectableServiceGoesToNeedsAttentionWithoutRemediating(@TempDir Path tempDir) {
        StubRemediator remediator = new StubRemediator();
        Context context = new Context(List.of(finding("F-1", "1.1"), agentFinding("F-2")));

        Outcome finalState = new Workflow(remediator, new AgentGuards(), noGate(tempDir),
                javaDetector(tempDir), null).run(context);

        assertEquals(Outcome.NEEDS_ATTENTION, finalState);
        assertEquals(List.of(), remediator.calls,
                "no attempt, no agent call and no build for a service the harness cannot identify");
        assertEquals(List.of(), context.getStacks());
    }

    @Test
    void anUndetectableServiceStillFilesEveryFinding(@TempDir Path tempDir) {
        StubRemediator remediator = new StubRemediator();
        Context context = new Context(List.of(finding("F-1", "1.1"), agentFinding("F-2")));

        new Workflow(remediator, new AgentGuards(), noGate(tempDir), javaDetector(tempDir), null)
                .run(context);

        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION, "F-2", Outcome.NEEDS_ATTENTION),
                context.getOutcomes(), "the report still names every finding a human has to look at");
        assertEquals(2, context.getRecords().size());
        assertEquals(0, context.getRecords().getFirst().attempts(),
                "nothing was attempted, and the record should not claim otherwise");
        assertNull(context.getRecords().getFirst().strategy(),
                "no strategy was ever picked");
    }

    @Test
    void anUndetectableServiceNeverReachesTheBuildGate(@TempDir Path tempDir) {
        StubRemediator remediator = new StubRemediator();
        Context context = new Context(List.of(finding("F-1", "1.1")));

        new Workflow(remediator, new AgentGuards(), noGate(tempDir), javaDetector(tempDir), null)
                .run(context);

        assertNull(context.getBuildGate(), "the gate is for services that were remediated");
    }

    @Test
    void aWorkflowWithNoStacksConfiguredRunsExactlyAsBefore(@TempDir Path tempDir) {
        StubRemediator remediator = new StubRemediator();
        Context context = new Context(List.of(finding("F-1", "1.1")));

        Outcome finalState = new Workflow(remediator, new AgentGuards(), noGate(tempDir),
                StackDetector.none(), null).run(context);

        assertEquals(Outcome.SUCCESS, finalState);
        assertEquals(List.of("update:F-1", "verify:F-1"), remediator.calls);
        assertEquals(List.of(), context.getStacks());
    }

    /** Collects decisions instead of pretending to open a PR. */
    static class RecordingAutonomyActions implements AutonomyActions {
        final List<String> performed = new ArrayList<>();

        @Override
        public void perform(String service, AutonomyDecision decision) {
            performed.add(service + ":" + decision.action());
        }
    }

    @Test
    void theAutonomyGateDecidesOnceTheServiceIsFinished(@TempDir Path tempDir) throws Exception {
        Files.writeString(tempDir.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);
        Context context = new Context(List.of(finding("F-1", "3.2.2")));
        RecordingAutonomyActions actions = new RecordingAutonomyActions();
        AutonomyGates gates = new AutonomyGates(List.of(new AutonomyRule(
                "auto-merge-green-dependency-bumps", Map.of(), AutonomyAction.AUTO_MERGE)));

        new Workflow(new Remediator(tempDir), new AgentGuards(), new BuildGate(List.of(), tempDir),
                StackDetector.none(), null, gates, actions)
                .run(context);

        assertEquals(AutonomyAction.AUTO_MERGE, context.getAutonomy().action());
        assertEquals("auto-merge-green-dependency-bumps", context.getAutonomy().rule());
        assertEquals(List.of("inventory-api:AUTO_MERGE"), actions.performed);
    }

    @Test
    void anUnconfiguredGateDecidesNothingAndPerformsNothing(@TempDir Path tempDir) throws Exception {
        Files.writeString(tempDir.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);
        Context context = new Context(List.of(finding("F-1", "3.2.2")));
        RecordingAutonomyActions actions = new RecordingAutonomyActions();

        new Workflow(new Remediator(tempDir), new AgentGuards(), new BuildGate(List.of(), tempDir),
                StackDetector.none(), null, new AutonomyGates(), actions)
                .run(context);

        assertNull(context.getAutonomy(), "an unconfigured gate must not invent a decision");
        assertEquals(List.of(), actions.performed);
    }

    // --- an agent that loses tests --------------------------------------------------------

    private static final String TWO_TESTS = """
            class OrderServiceTest {
                @Test
                void a() {
                }

                @Test
                void b() {
                }
            }
            """;

    private static final String ONE_TEST = """
            class OrderServiceTest {
                @Test
                void a() {
                }
            }
            """;

    private static final String TEST_FILE = "src/test/java/OrderServiceTest.java";

    /** A real remediator whose agent rewrites the seeded test file with one test gone. */
    private static Remediator agentLosingATest(Path tempDir) throws IOException {
        Path target = tempDir.resolve(TEST_FILE);
        Files.createDirectories(target.getParent());
        Files.writeString(target, TWO_TESTS, StandardCharsets.UTF_8);
        return new Remediator(f -> new LlmResponse(List.of(
                new ToolCall("writeFile", TEST_FILE, ONE_TEST))), tempDir);
    }

    @Test
    void anAgentThatLosesTestsSendsTheFindingToAHumanOnTheFirstAttempt(@TempDir Path tempDir)
            throws IOException {
        Context context = new Context(List.of(agentFinding("F-1")));

        new Workflow(agentLosingATest(tempDir), new AgentGuards(), noGate(tempDir),
                StackDetector.none(), null).run(context);

        FindingRecord record = context.getRecords().getFirst();
        assertEquals(Outcome.NEEDS_ATTENTION, record.outcome());
        assertEquals(1, record.attempts(), "there is nothing to retry: the agent did this on purpose");
        assertEquals(List.of(new GuardDecision(GuardRule.When.BEFORE, null, Verdict.ALLOW),
                        new GuardDecision(GuardRule.When.TOOL,
                                "agent-write-reduces-the-tests-that-will-run", Verdict.MANUAL_REVIEW)),
                record.guardDecisions());
    }

    @Test
    void theRecordCarriesWhatTheCensusCounted(@TempDir Path tempDir) throws IOException {
        Context context = new Context(List.of(agentFinding("F-1")));

        new Workflow(agentLosingATest(tempDir), new AgentGuards(), noGate(tempDir),
                StackDetector.none(), null).run(context);

        FindingRecord record = context.getRecords().getFirst();
        assertEquals(2, record.testsBefore());
        assertEquals(1, record.testsAfter());
    }

    @Test
    void theFilesARefusedAgentWroteAreStillNamed(@TempDir Path tempDir) throws IOException {
        // This refusal leaves real changes behind, so a report that did not name them would be
        // wrong about what is in the working tree - and ChangeKind would misread the service.
        Context context = new Context(List.of(agentFinding("F-1")));

        new Workflow(agentLosingATest(tempDir), new AgentGuards(), noGate(tempDir),
                StackDetector.none(), null).run(context);

        assertEquals(List.of(TEST_FILE), context.getRecords().getFirst().filesChanged());
    }

    @Test
    void anAgentThatLosesNoTestsRecordsNoCounts(@TempDir Path tempDir) throws IOException {
        Path target = tempDir.resolve(TEST_FILE);
        Files.createDirectories(target.getParent());
        Files.writeString(target, TWO_TESTS, StandardCharsets.UTF_8);
        Remediator remediator = new Remediator(f -> new LlmResponse(List.of(
                new ToolCall("writeFile", TEST_FILE, TWO_TESTS))), tempDir);
        Context context = new Context(List.of(agentFinding("F-1")));

        new Workflow(remediator, new AgentGuards(), noGate(tempDir), StackDetector.none(), null)
                .run(context);

        FindingRecord record = context.getRecords().getFirst();
        assertNull(record.testsBefore(), "nothing was lost, so the report has nothing to say");
        assertNull(record.testsAfter());
    }

    /** A stub whose deterministic update lands a file, so the build has something to judge. */
    private static StubRemediator writingRemediator() {
        StubRemediator remediator = new StubRemediator();
        remediator.writes = "pom.xml";
        return remediator;
    }

    /**
     * A gate with a script instead of a shell: each call takes the next verdict, and the last one
     * repeats. Lets a test say "red, then the agent fixed it" without a portable shell command.
     */
    static class ScriptedBuildGate extends BuildGate {
        private final List<Verdict> verdicts;
        int calls;

        ScriptedBuildGate(Verdict... verdicts) {
            super(List.of(), Path.of("."));
            this.verdicts = List.of(verdicts);
        }

        @Override
        public BuildGateResult evaluate(List<String> detected) {
            Verdict verdict = verdicts.get(Math.min(calls++, verdicts.size() - 1));
            return new BuildGateResult(verdict, detected,
                    List.of(new BuildGateResult.StepResult("scripted", verdict == Verdict.ALLOW, 0)));
        }
    }

    @Test
    void aDependencyUpdateThatBreaksTheBuildIsHandedToTheAgent() {
        StubRemediator remediator = writingRemediator();
        BuildGate buildGate = new ScriptedBuildGate(Verdict.BLOCK, Verdict.ALLOW);
        Context context = new Context(List.of(finding("F-1", "1.1")));

        Outcome finalState = new Workflow(remediator, new AgentGuards(), buildGate).run(context);

        assertEquals(List.of("update:F-1", "verify:F-1", "agent:F-1:2", "verify:F-1"),
                remediator.calls, "the second attempt should be the agent's, not the same rewrite");
        assertEquals(Outcome.SUCCESS, finalState);
    }

    @Test
    void aBuildThatCannotSayEscalatesTheSameWay() {
        StubRemediator remediator = writingRemediator();
        BuildGate buildGate = new ScriptedBuildGate(Verdict.MANUAL_REVIEW, Verdict.ALLOW);
        Context context = new Context(List.of(finding("F-1", "1.1")));

        new Workflow(remediator, new AgentGuards(), buildGate).run(context);

        assertEquals(List.of("update:F-1", "verify:F-1", "agent:F-1:2", "verify:F-1"),
                remediator.calls);
    }

    @Test
    void aDependencyUpdateThatBuildsIsLeftAlone(@TempDir Path tempDir) {
        StubRemediator remediator = writingRemediator();
        BuildGate buildGate = new BuildGate(List.of(gateStep("exit 0", Verdict.BLOCK)), tempDir);
        Context context = new Context(List.of(finding("F-1", "1.1")));

        Outcome finalState = new Workflow(remediator, new AgentGuards(), buildGate).run(context);

        assertEquals(Outcome.SUCCESS, finalState);
        assertEquals(List.of("update:F-1", "verify:F-1"), remediator.calls);
    }

    @Test
    void anUpdateThatWroteNothingIsNeverBuilt(@TempDir Path tempDir) {
        // The stub declares no writes, so there is nothing on disk a build could have an
        // opinion about - and a failing gate must not turn that into three agent attempts.
        StubRemediator remediator = new StubRemediator();
        BuildGate buildGate = new BuildGate(List.of(gateStep("exit 1", Verdict.BLOCK)), tempDir);
        Context context = new Context(List.of(finding("F-1", "1.1")));

        new Workflow(remediator, new AgentGuards(), buildGate).run(context);

        assertEquals(List.of("update:F-1", "verify:F-1"), remediator.calls);
    }

    @Test
    void anAgentThatCannotFixTheBuildEitherSpendsTheRemainingAttemptsAndAsksForAHuman(
            @TempDir Path tempDir) {
        StubRemediator remediator = writingRemediator();
        BuildGate buildGate = new BuildGate(List.of(gateStep("exit 1", Verdict.BLOCK)), tempDir);
        Context context = new Context(List.of(finding("F-1", "1.1")));

        new Workflow(remediator, new AgentGuards(), buildGate).run(context);

        assertEquals(List.of("update:F-1", "verify:F-1", "agent:F-1:2", "verify:F-1",
                "agent:F-1:3", "verify:F-1"), remediator.calls);
        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION), context.getOutcomes());
    }

    @Test
    void aFindingTheAgentAlwaysOwnedIsNotBuiltPerAttempt(@TempDir Path tempDir) {
        StubRemediator remediator = writingRemediator();
        BuildGate buildGate = new BuildGate(List.of(gateStep("exit 1", Verdict.BLOCK)), tempDir);
        Context context = new Context(List.of(agentFinding("F-1")));

        new Workflow(remediator, new AgentGuards(), buildGate).run(context);

        assertEquals(List.of("agent:F-1:1", "verify:F-1"), remediator.calls,
                "verification and the guards judge an agent finding; the service gate has the last word");
    }

    @Test
    void theRecordOfAnEscalatedFindingNamesTheAgentAndSaysWhy() {
        StubRemediator remediator = writingRemediator();
        BuildGate buildGate = new ScriptedBuildGate(Verdict.BLOCK, Verdict.ALLOW);
        Context context = new Context(List.of(finding("F-1", "1.1")));

        new Workflow(remediator, new AgentGuards(), buildGate).run(context);

        FindingRecord record = context.getRecords().get(0);
        assertEquals(Strategy.AGENT_REMEDIATION, record.strategy());
        assertTrue(record.escalated(), "a direct finding the agent finished has to say how it got there");
        assertEquals(2, record.attempts());
    }

    @Test
    void anEscalatedAttemptIsScreenedByTheGuardsLikeAnyOtherAgentCall(@TempDir Path tempDir) {
        StubRemediator remediator = writingRemediator();
        BuildGate buildGate = new BuildGate(List.of(gateStep("exit 1", Verdict.BLOCK)), tempDir);
        AgentGuards guards = new AgentGuards(List.of(new GuardRule("no-agent-on-this-package",
                GuardRule.When.BEFORE, Map.of("packageName", "example:example"),
                Verdict.MANUAL_REVIEW)));
        Context context = new Context(List.of(finding("F-1", "1.1")));

        new Workflow(remediator, guards, buildGate).run(context);

        assertEquals(List.of("update:F-1", "verify:F-1"), remediator.calls,
                "the escalation is an agent invocation, and a BEFORE guard gets to refuse it");
        assertEquals(Map.of("F-1", Outcome.NEEDS_ATTENTION), context.getOutcomes());
    }
}
