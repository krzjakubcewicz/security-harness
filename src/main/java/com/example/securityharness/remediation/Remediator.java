package com.example.securityharness.remediation;

import com.example.securityharness.agent.LlmResponse;
import com.example.securityharness.agent.LlmStub;
import com.example.securityharness.agent.MockLlmStub;
import com.example.securityharness.agent.SuspectedInjection;
import com.example.securityharness.agent.TestCensus;
import com.example.securityharness.agent.ToolCall;
import com.example.securityharness.agent.Toolbox;
import com.example.securityharness.findings.Finding;
import com.example.securityharness.guards.AgentGuards;
import com.example.securityharness.guards.GuardRule;
import com.example.securityharness.guards.GuardViolation;
import com.example.securityharness.guards.TestsLost;
import com.example.securityharness.policy.Verdict;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The side-effecting operations the workflow performs. Methods are overridable so
 * tests can drive the state machine without touching pom.xml or a real agent.
 * Nothing here sees the context: the harness owns the state and the retry limit.
 */
public class Remediator {
    private static final Logger log = LoggerFactory.getLogger(Remediator.class);

    /**
     * The rule a refused read is reported under. Not a guards.yaml rule: content that tries to
     * instruct the agent is a containment problem, and containment fails closed whatever the
     * config says - the same reason WorkDirPaths is not configurable either.
     */
    private static final String INJECTION_RULE = "agent-read-untrusted-content-looks-like-an-injection";

    /**
     * The rule a shrinking test count is reported under - named for what is measured, because a
     * test deleted and a test disabled are the same loss. Like INJECTION_RULE and unlike
     * guards.yaml this is not policy: a remediation that verifies green because the failing tests
     * no longer run is not a remediation, whatever a config file says.
     */
    private static final String LOST_TESTS_RULE = "agent-write-reduces-the-tests-that-will-run";

    private final LlmStub llmStub;

    /** Root the agent's file tool calls land in. Null means log-only: nothing is written. */
    private final Path workDir;

    /** What the agent is allowed to do. Null when there is no work directory to act in. */
    private final Toolbox toolbox;

    /** Counts the tests in what the agent writes. Null alongside the toolbox, for the same reason. */
    private final TestCensus census;

    /** Which paths the agent may write. Empty rules allow everything the tools themselves allow. */
    private final AgentGuards guards;

    /**
     * The file this service's stack declares dependency versions in, or null when the stack could
     * not say (see StackDetector.dependencyFile). Set once by the workflow's stack step, before
     * any finding is processed; null leaves DependencyFile guessing from the package name as it
     * always did. This is not run state - it is what the service is, which does not change.
     */
    private String stackDependencyFile;

    /** Told to the remediator by the workflow's stack step, before the first finding. */
    public void setStackDependencyFile(String stackDependencyFile) {
        this.stackDependencyFile = stackDependencyFile;
    }

    public Remediator() {
        this(new MockLlmStub(), null, new AgentGuards());
    }

    public Remediator(Path workDir) {
        this(new MockLlmStub(), workDir, new AgentGuards());
    }

    public Remediator(LlmStub llmStub) {
        this(llmStub, null, new AgentGuards());
    }

    public Remediator(LlmStub llmStub, Path workDir) {
        this(llmStub, workDir, new AgentGuards());
    }

    public Remediator(Path workDir, AgentGuards guards) {
        this(new MockLlmStub(), workDir, guards);
    }

    public Remediator(LlmStub llmStub, Path workDir, AgentGuards guards) {
        this.llmStub = llmStub;
        this.workDir = workDir == null ? null : workDir.toAbsolutePath().normalize();
        this.toolbox = this.workDir == null ? null : new Toolbox(this.workDir);
        this.census = this.workDir == null ? null : new TestCensus(this.workDir);
        this.guards = guards;
    }

    /**
     * Rewrites the version the service declares for this package. The write goes through the same
     * toolbox the agent uses, so it lands in the ledger ChangeVerifier checks against git and
     * inherits the tools' work-directory containment - a write around it would abort the run as an
     * undeclared change.
     *
     * <p>Nothing is written in log-only mode, or when the package turns out not to be declared in
     * this service at all; verification then fails on its own rather than being told to.
     */
    public void applyDependencyUpdate(Finding finding) {
        log.info("  DEPENDENCY_UPDATE {} {} -> {}", finding.packageName(), finding.installedVersion(), finding.fixedVersion());
        if (workDir == null || finding.fixedVersion() == null) {
            return;
        }
        String fileName = DependencyFile.nameFor(finding.packageName(), stackDependencyFile);
        String existing = readIfPresent(workDir.resolve(fileName));
        if (existing == null) {
            log.info("    no {} in {}", fileName, workDir);
            return;
        }
        String updated = DependencyFile.withVersion(existing, finding.packageName(), finding.fixedVersion());
        if (updated == null) {
            logNotRewritten(fileName, existing, finding);
            return;
        }
        toolbox.call(new ToolCall("writeFile", fileName, updated));
    }

    /**
     * Why nothing was written. "Not declared" and "declared, but as a property reference" are
     * different facts about the pom, and logging the first for the second would send whoever reads
     * the run looking for a dependency that is right there.
     */
    private static void logNotRewritten(String fileName, String content, Finding finding) {
        String declared = DependencyFile.declaredVersion(content, finding.packageName());
        if (DependencyFile.isPropertyReference(declared)) {
            log.info("    {} declares {} as {} - not rewriting a property reference",
                    fileName, finding.packageName(), declared);
        } else {
            log.info("    {} does not declare {}", fileName, finding.packageName());
        }
    }

    /**
     * Runs the agent over the finding and applies whatever tool calls it returns. Every call is
     * screened against the 'when: tool' guards before the first one is applied, and every read
     * runs before every write, so a refusal - by a guard, or by what a read found - leaves the
     * work directory exactly as it was. No half-applied remediation.
     *
     * <p>One refusal is the exception, and has to be: whether the agent left fewer tests running
     * than it found cannot be known until the writes have landed. That one throws with the changes
     * still on disk, because the diff is the thing a person has to read.
     */
    public LlmResponse invokeAgent(Finding finding, int attempt) {
        LlmResponse response = llmStub.analyze(finding);
        log.info("  AGENT_REMEDIATION {} (attempt {}) - {} tool calls", finding.packageName(), attempt, response.toolCalls().size());
        for (ToolCall toolCall : response.toolCalls()) {
            log.info("    {} {}", toolCall.tool(), toolCall.filePath());
            GuardRule refused = guards.matchingToolRule(toolCall, finding);
            if (refused != null) {
                throw new GuardViolation(refused.name(), refused.action(), toolCall);
            }
        }
        if (toolbox != null) {
            // Reads first, whatever order the agent asked in: a read is the only call that can be
            // refused by what it finds, and that refusal has to leave the work directory untouched.
            apply(response, true);
            List<ToolCall> writes = response.toolCalls().stream()
                    .filter(call -> !toolbox.isReadOnly(call)).toList();
            Map<String, Integer> before = census.across(writes);
            apply(response, false);
            requireNoTestsLost(writes, before, census.across(writes));
        }
        return response;
    }

    /**
     * Refuses a remediation that left fewer tests running than it found. The total decides - an
     * agent that moved a test between two files it wrote has lost nothing - while the file whose
     * own count fell is what the violation names, because that is where the reviewer has to look.
     */
    private static void requireNoTestsLost(List<ToolCall> writes, Map<String, Integer> before,
                                           Map<String, Integer> after) {
        if (writes.isEmpty()) {
            return;
        }
        int liveBefore = total(before);
        int liveAfter = total(after);
        log.info("    tests that will run: {} -> {}", liveBefore, liveAfter);
        if (liveAfter >= liveBefore) {
            return;
        }
        for (ToolCall write : writes) {
            if (after.get(write.filePath()) < before.get(write.filePath())) {
                throw new TestsLost(LOST_TESTS_RULE, write, liveBefore, liveAfter);
            }
        }
        // The total fell but no single file did, which the arithmetic does not allow.
        throw new IllegalStateException("Test count fell from " + liveBefore + " to " + liveAfter
                + " but no written file lost a test");
    }

    private static int total(Map<String, Integer> counts) {
        return counts.values().stream().mapToInt(Integer::intValue).sum();
    }

    /** The read-only half of the response, or the rest of it, in the order the agent asked. */
    private void apply(LlmResponse response, boolean readOnly) {
        for (ToolCall toolCall : response.toolCalls()) {
            if (toolbox.isReadOnly(toolCall) != readOnly) {
                continue;
            }
            try {
                toolbox.call(toolCall);
            } catch (SuspectedInjection injection) {
                log.warn("    {}", injection.getMessage());
                throw new GuardViolation(INJECTION_RULE, Verdict.MANUAL_REVIEW, toolCall);
            }
        }
    }

    /** The root written paths are relative to, or null in log-only mode. */
    public Path workDir() {
        return workDir;
    }

    /**
     * Every path the agent's tools have written so far, each once. ChangeVerifier compares this
     * against git; log-only mode writes nothing and so declares nothing.
     */
    public Set<Path> filesWritten() {
        return toolbox == null ? Set.of() : toolbox.filesWritten();
    }

    /**
     * Reports whether the finding is actually fixed, by re-reading what the remediation wrote.
     * What counts as fixed depends on which remediation ran: the dependency-update path has to
     * leave the fixed version declared in the service's dependency file, while the agent's
     * contract is the marker it leaves in the pom - F-40218's snakeyaml is transitive and is not
     * declared anywhere in the pom, so there is no version there to assert. Which path a finding
     * takes is decided by its own path field (Workflow).
     */
    public boolean verify(Finding finding, Strategy strategy) {
        boolean passed = strategy == Strategy.DEPENDENCY_UPDATE
                ? fixedVersionDeclared(finding)
                : remediationMarkerPresent(finding);
        log.info("  verify {}: {}", finding.id(), passed ? "PASS" : "FAIL");
        return passed;
    }

    /** True when the service's dependency file now declares exactly this finding's fixed version. */
    private boolean fixedVersionDeclared(Finding finding) {
        if (workDir == null || finding.fixedVersion() == null) {
            return false;
        }
        String content = readIfPresent(workDir.resolve(
                DependencyFile.nameFor(finding.packageName(), stackDependencyFile)));
        return content != null
                && finding.fixedVersion().equals(DependencyFile.declaredVersion(content, finding.packageName()));
    }

    /** True when workDir/pom.xml carries this finding's "CVE-... fixed" marker. */
    private boolean remediationMarkerPresent(Finding finding) {
        if (workDir == null) {
            return false;
        }
        String content = readIfPresent(workDir.resolve("pom.xml"));
        return content != null && content.contains(remediationMarker(finding.cve()));
    }

    /**
     * The comment the agent leaves at the top of a remediated file, as the llm-responses fixtures
     * spell it. One place, because the agent writes it and verification reads it back - two
     * spellings would silently never match.
     */
    private static String remediationMarker(String cve) {
        return "<!-- " + cve + " fixed -->";
    }

    /** The file's text, or null when there is no such file. */
    private static String readIfPresent(Path file) {
        if (!Files.isRegularFile(file)) {
            return null;
        }
        try {
            return Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + file, e);
        }
    }
}
