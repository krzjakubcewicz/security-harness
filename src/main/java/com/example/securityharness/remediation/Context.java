package com.example.securityharness.remediation;

import com.example.securityharness.autonomy.AutonomyDecision;
import com.example.securityharness.buildgate.BuildGateResult;
import com.example.securityharness.findings.Finding;
import com.example.securityharness.guards.GuardDecision;
import com.example.securityharness.guards.GuardRule;
import com.example.securityharness.policy.Verdict;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Mutable state of one remediation run: the findings queue, where we are in it, the retry
 * counter, and what each finding ended as. {@link Workflow} drives it; the outcome is only
 * set once, when the run is over.
 */
public class Context {

    public static final int DEFAULT_MAX_ATTEMPTS = 3;

    private final List<Finding> findings;
    private final int maxAttempts;

    /** One entry per finished finding, in the order they were processed. */
    private final List<FindingRecord> records = new ArrayList<>();

    /** Buffers for the finding in flight; recordOutcome drains them into a FindingRecord. */
    private final List<GuardDecision> guardDecisions = new ArrayList<>();
    private final List<String> filesChanged = new ArrayList<>();
    private boolean verified;

    /** Tests that would have run across what the agent wrote, and that will now. Null when uncounted. */
    private Integer testsBefore;
    private Integer testsAfter;

    /** Null until the run finishes. */
    private Outcome outcome;

    private int index = 0;
    private int attempt = 0;
    private Strategy strategy;

    /** Whether the build sent the current finding from a deterministic change to the agent. */
    private boolean escalated;
    private BuildGateResult buildGate;

    /** What the autonomy gate decided about this service's changes. Null until it has run. */
    private AutonomyDecision autonomy;

    /** What the service was detected as. Empty until the workflow's stack step has run. */
    private List<String> stacks = List.of();

    public Context(List<Finding> findings) {
        this(findings, DEFAULT_MAX_ATTEMPTS);
    }

    public Context(List<Finding> findings, int maxAttempts) {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be at least 1, was " + maxAttempts);
        }
        this.findings = List.copyOf(findings);
        this.maxAttempts = maxAttempts;
    }

    /** How the run ended, or null while it is still going. */
    public Outcome getOutcome() {
        return outcome;
    }

    /** Closes the run with this outcome and hands it straight back to the caller. */
    public Outcome finish(Outcome outcome) {
        this.outcome = outcome;
        return outcome;
    }

    public boolean hasCurrentFinding() {
        return index < findings.size();
    }

    public Finding currentFinding() {
        if (!hasCurrentFinding()) {
            throw new IllegalStateException("No current finding: all " + findings.size() + " processed");
        }
        return findings.get(index);
    }

    public Strategy getStrategy() {
        return strategy;
    }

    public void setStrategy(Strategy strategy) {
        this.strategy = strategy;
    }

    /** True once the build refused a deterministic change and the agent was given the finding. */
    public boolean isEscalated() {
        return escalated;
    }

    /**
     * Hands the current finding to the agent for whatever attempts it has left. The strategy it
     * was routed with was a guess from the finding's path; a build that will not go green is the
     * harness finding out, and the remaining attempts are better spent on the code than on the
     * same rewrite again.
     */
    public void escalateToAgent() {
        this.strategy = Strategy.AGENT_REMEDIATION;
        this.escalated = true;
    }

    /**
     * Whether this finding's attempts have put anything on disk. Nothing written is nothing to
     * build, and asking a build about it costs a full compile-and-test cycle to learn that.
     */
    public boolean hasFilesChanged() {
        return !filesChanged.isEmpty();
    }

    public int getAttempt() {
        return attempt;
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    public void startAttempts() {
        attempt = 1;
    }

    public void nextAttempt() {
        attempt++;
    }

    public boolean attemptsExhausted() {
        return attempt >= maxAttempts;
    }

    /** Files the current finding's final state and moves the cursor to the next one. */
    public void recordOutcome(Outcome outcome) {
        records.add(FindingRecord.of(currentFinding(), strategy, escalated, attempt, verified,
                guardDecisions, filesChanged, testsBefore, testsAfter, outcome));
        index++;
        attempt = 0;
        strategy = null;
        escalated = false;
        verified = false;
        testsBefore = null;
        testsAfter = null;
        guardDecisions.clear();
        filesChanged.clear();
    }

    /** Derived from {@link #getRecords()} so there is one account of a run, not two. */
    public Map<String, Outcome> getOutcomes() {
        Map<String, Outcome> outcomes = new LinkedHashMap<>();
        for (FindingRecord record : records) {
            outcomes.put(record.id(), record.outcome());
        }
        return Collections.unmodifiableMap(outcomes);
    }

    /** The full trace of every finished finding - what the run report serialises. */
    public List<FindingRecord> getRecords() {
        return List.copyOf(records);
    }

    /** How many findings this service was handed, finished or not. */
    public int findingCount() {
        return findings.size();
    }

    /** The service every finding in this context belongs to, or null when there are none. */
    public String serviceName() {
        return findings.isEmpty() ? null : findings.get(0).service();
    }

    /** {@code ruleName} is null when nothing matched - the implicit ALLOW. */
    public void recordGuardDecision(GuardRule.When phase, String ruleName, Verdict action) {
        guardDecisions.add(new GuardDecision(phase, ruleName, action));
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    /** What the census found either side of the current finding's agent writes. */
    public void setTestCounts(int before, int after) {
        this.testsBefore = before;
        this.testsAfter = after;
    }

    public void addFileChanged(String path) {
        filesChanged.add(path);
    }

    public BuildGateResult getBuildGate() {
        return buildGate;
    }

    public void setBuildGate(BuildGateResult buildGate) {
        this.buildGate = buildGate;
    }

    public AutonomyDecision getAutonomy() {
        return autonomy;
    }

    public void setAutonomy(AutonomyDecision autonomy) {
        this.autonomy = autonomy;
    }

    /**
     * The stacks detected in this service. Unlike the per-finding buffers, this is settled once
     * for the whole run - recordOutcome must not clear it.
     */
    public List<String> getStacks() {
        return stacks;
    }

    public void setStacks(List<String> stacks) {
        this.stacks = List.copyOf(stacks);
    }
}
