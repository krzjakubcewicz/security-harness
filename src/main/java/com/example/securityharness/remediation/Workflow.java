package com.example.securityharness.remediation;

import com.example.securityharness.autonomy.AutonomyActions;
import com.example.securityharness.autonomy.AutonomyDecision;
import com.example.securityharness.autonomy.AutonomyGates;
import com.example.securityharness.buildgate.BuildGate;
import com.example.securityharness.buildgate.BuildGateResult;
import com.example.securityharness.findings.Finding;
import com.example.securityharness.guards.AgentGuards;
import com.example.securityharness.guards.GuardRule;
import com.example.securityharness.guards.GuardViolation;
import com.example.securityharness.guards.TestsLost;
import com.example.securityharness.policy.Verdict;
import com.example.securityharness.stack.StackDetector;
import com.example.securityharness.verify.ChangeVerificationFailure;
import com.example.securityharness.verify.ChangeVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * The remediation pipeline. One instance drives every finding in the context sequentially:
 * pick a strategy, remediate, verify, build, retry up to the context's limit, record what
 * happened. A strategy is a guess from the finding's path, and the build is what corrects it: a
 * deterministic change that will not build hands the finding to the agent for its remaining
 * attempts. The retry limit belongs to the harness - nothing the agent returns can extend it.
 */
public class Workflow {
    Logger log = LoggerFactory.getLogger(Workflow.class);

    private final Remediator remediator;
    private final AgentGuards guards;
    private final BuildGate buildGate;

    /** Checks the agent's declared writes against git once the queue drains. Null = not checked. */
    private final ChangeVerifier changeVerifier;

    /** What the service is. Never null - a workflow with no stacks configured detects nothing. */
    private final StackDetector stackDetector;

    /** What to do with the changes once they are made. Never null; may be unconfigured. */
    private final AutonomyGates autonomyGates;

    /** How to carry a decision out. Only consulted when the gates are configured. */
    private final AutonomyActions autonomyActions;

    public Workflow(Remediator remediator, AgentGuards guards) {
        this(remediator, guards, new BuildGate(List.of(), Path.of(".")));
    }

    public Workflow(Remediator remediator, AgentGuards guards, BuildGate buildGate) {
        this(remediator, guards, buildGate, null);
    }

    public Workflow(Remediator remediator, AgentGuards guards, BuildGate buildGate,
                               ChangeVerifier changeVerifier) {
        this(remediator, guards, buildGate, StackDetector.none(), changeVerifier);
    }

    public Workflow(Remediator remediator, AgentGuards guards, BuildGate buildGate,
                               StackDetector stackDetector, ChangeVerifier changeVerifier) {
        this(remediator, guards, buildGate, stackDetector, changeVerifier,
                new AutonomyGates(), (service, decision) -> { });
    }

    public Workflow(Remediator remediator, AgentGuards guards, BuildGate buildGate,
                               StackDetector stackDetector, ChangeVerifier changeVerifier,
                               AutonomyGates autonomyGates, AutonomyActions autonomyActions) {
        this.remediator = remediator;
        this.guards = guards;
        this.buildGate = buildGate;
        this.stackDetector = stackDetector;
        this.changeVerifier = changeVerifier;
        this.autonomyGates = autonomyGates;
        this.autonomyActions = autonomyActions;
    }

    /** Works through every finding, then gates the service as a whole. */
    public Outcome run(Context context) {
        try {
            if (!determineStack(context)) {
                return context.finish(Outcome.NEEDS_ATTENTION);
            }
            while (context.hasCurrentFinding()) {
                processFinding(context);
            }
            // Before the build gate on purpose: once mvn has run, its target/ output is an
            // undeclared change and every run would fail verification.
            if (changeVerifier != null) {
                changeVerifier.verify(remediator.filesWritten());
            }
            BuildGateResult gate = buildGate.evaluate(context.getStacks());
            context.setBuildGate(gate);
            decideAutonomy(context);
            return context.finish(switch (gate.action()) {
                case ALLOW -> Outcome.SUCCESS;
                case BLOCK, MANUAL_REVIEW -> Outcome.NEEDS_ATTENTION;
            });
        } catch (ChangeVerificationFailure e) {
            // Not a remediation outcome: the harness cannot account for what it changed, so this
            // escapes to main and ends the process instead of becoming one service a human reads.
            throw e;
        } catch (RuntimeException e) {
            log.error("Unexpected error: {}", e.getMessage());
            return context.finish(Outcome.NEEDS_ATTENTION);
        }
    }

    /**
     * The first step of a run: what is this service? Everything after it depends on the answer -
     * which file a dependency update rewrites, which commands the build gate runs - so it is
     * settled once, here, before anything has been changed.
     *
     * <p>False when the harness cannot say what the service is. There is no point spending three
     * agent attempts and a build on a service whose remediation could not be verified and whose
     * build could not be proven green, so every finding is filed for a human now rather than
     * after the fact. Every finding is still recorded, unattempted, so the report names them all.
     */
    private boolean determineStack(Context context) {
        List<String> stacks = stackDetector.detect();
        context.setStacks(stacks);
        if (!stackDetector.isConfigured()) {
            return true;
        }
        if (stacks.isEmpty()) {
            log.warn("No stack detected in {} (looked for {}) - manual review",
                    stackDetector.serviceDirectory(), stackDetector.markerNames());
            while (context.hasCurrentFinding()) {
                context.recordOutcome(Outcome.NEEDS_ATTENTION);
            }
            return false;
        }
        log.info("Detected stack(s) {} in {}", stacks, stackDetector.serviceDirectory());
        remediator.setStackDependencyFile(stackDetector.dependencyFile(stacks));
        return true;
    }

    /**
     * What happens to the changes now they exist. Last, because it is the only step that needs
     * every other one's answer - which findings were remediated, what they touched, and whether
     * the build went green. It decides nothing about the service's outcome: a run can succeed and
     * still be routed to a human rather than merged.
     */
    private void decideAutonomy(Context context) {
        if (!autonomyGates.isConfigured()) {
            return;
        }
        String service = context.serviceName();
        AutonomyDecision decision = autonomyGates.decide(service, context.getRecords(),
                context.getBuildGate(), stackDetector.dependencyFile(context.getStacks()));
        context.setAutonomy(decision);
        log.info("  autonomy: {} ({}) - {}", decision.action(),
                decision.rule() == null ? "no gate matched" : decision.rule(), decision.reason());
        autonomyActions.perform(service, decision);
    }

    /** Takes one finding as far as it goes and records its outcome, leaving the cursor on the next. */
    private void processFinding(Context context) {
        Finding finding = context.currentFinding();
        log.info("{} {} {} {} ({})", finding.id(), finding.cve(), finding.severity(), finding.packageName(), finding.service());

        context.setStrategy(finding.path().equals("direct")
                ? Strategy.DEPENDENCY_UPDATE
                : Strategy.AGENT_REMEDIATION);
        // Nothing to upgrade to: the update would be a no-op and every retry an identical
        // one, so this goes to a human now rather than after maxAttempts of nothing.
        if (context.getStrategy() == Strategy.DEPENDENCY_UPDATE && finding.fixedVersion() == null) {
            log.info("  no fixed version published for {}", finding.packageName());
            needsAttention(context);
            return;
        }

        context.startAttempts();
        while (!attempt(context)) {
            if (context.attemptsExhausted()) {
                needsAttention(context);
                return;
            }
            context.nextAttempt();
        }
    }

    /**
     * One attempt at the current finding: guards, remediation, verification, the build, guards
     * again.
     * True when the finding is finished and its outcome recorded, false when it should be retried.
     */
    private boolean attempt(Context context) {
        Finding finding = context.currentFinding();
        boolean agent = context.getStrategy() == Strategy.AGENT_REMEDIATION;

        if (agent) {
            GuardRule matched = guards.matchingBeforeRule(finding, context);
            Verdict decision = AgentGuards.actionOf(matched);
            context.recordGuardDecision(GuardRule.When.BEFORE, nameOf(matched), decision);
            if (decision != Verdict.ALLOW) {
                return record(context, decision);
            }
        }

        try {
            remediate(context);
        } catch (GuardViolation violation) {
            // Every tool call is screened before the first one is applied, so a refusal leaves the
            // work directory exactly as it was - there is nothing half-applied to retry. TestsLost
            // is the exception: it can only be known after the writes, so those changes stay on
            // disk and go out with the pull request for a person to read.
            log.info("  {}", violation.getMessage());
            context.recordGuardDecision(GuardRule.When.TOOL, violation.ruleName(), violation.action());
            if (violation instanceof TestsLost lost) {
                context.setTestCounts(lost.before(), lost.after());
            }
            needsAttention(context);
            return true;
        }

        boolean verified = remediator.verify(finding, context.getStrategy());
        context.setVerified(verified);
        if (!verified) {
            return false;
        }

        if (!buildStillGreen(context)) {
            return false;
        }

        Verdict decision = Verdict.ALLOW;
        if (agent) {
            GuardRule matched = guards.matchingAfterRule(finding, context);
            decision = AgentGuards.actionOf(matched);
            context.recordGuardDecision(GuardRule.When.AFTER, nameOf(matched), decision);
        }
        return record(context, decision);
    }

    /**
     * Whether the change this attempt made can still be built. A version bump that compiles into a
     * broken service is exactly what a deterministic rewrite cannot see and an agent can fix - by
     * editing the code that called what moved - so a red build here is a referral, not a failure.
     *
     * <p>Only deterministic changes and the agent attempts an escalation handed a finding to are
     * asked. A finding the agent owned from the start is judged by verification and the guards, as
     * it always was, and the service gate still has the last word on every one of them.
     *
     * <p>False sends the finding back to the retry loop, which either spends another attempt on it
     * - now the agent's - or files it for a human. The escalation costs an attempt rather than
     * being granted new ones: the retry limit belongs to the harness.
     */
    private boolean buildStillGreen(Context context) {
        // Nothing on disk is nothing to build, and asking would buy a full compile-and-test cycle
        // to be told what the attempt before it already said.
        if (!isProbed(context) || !context.hasFilesChanged()) {
            return true;
        }
        BuildGateResult probe = buildGate.evaluate(context.getStacks());
        if (probe.action() == Verdict.ALLOW) {
            return true;
        }
        if (context.isEscalated()) {
            log.info("  build still {} after the agent's attempt {}", probe.action(), context.getAttempt());
            return false;
        }
        log.info("  build {} after the dependency update - handing {} to the agent",
                probe.action(), context.currentFinding().id());
        context.escalateToAgent();
        return false;
    }

    /** Deterministic changes, and the agent attempts an escalation handed the finding to. */
    private boolean isProbed(Context context) {
        return context.getStrategy() == Strategy.DEPENDENCY_UPDATE || context.isEscalated();
    }

    /** Files the outcome a verdict implies. Always true: a verdict ends the finding either way. */
    private boolean record(Context context, Verdict verdict) {
        switch (verdict) {
            case ALLOW -> context.recordOutcome(Outcome.SUCCESS);
            case BLOCK, MANUAL_REVIEW -> needsAttention(context);
        }
        return true;
    }

    /** The attempt count is zero when nothing was ever tried, and the log should not claim otherwise. */
    private void needsAttention(Context context) {
        log.info("  needs attention: {}{}", context.currentFinding().id(),
                context.getAttempt() == 0 ? "" : " after " + context.getAttempt() + " attempt(s)");
        context.recordOutcome(Outcome.NEEDS_ATTENTION);
    }

    private static String nameOf(GuardRule matched) {
        return matched == null ? null : matched.name();
    }

    private void remediate(Context context) {
        Finding finding = context.currentFinding();
        Set<Path> before = Set.copyOf(remediator.filesWritten());
        try {
            switch (context.getStrategy()) {
                case DEPENDENCY_UPDATE -> remediator.applyDependencyUpdate(finding);
                case AGENT_REMEDIATION -> remediator.invokeAgent(finding, context.getAttempt());
            }
        } finally {
            // In a finally because a refusal no longer implies nothing was written: TestsLost
            // leaves real changes, and a report that did not name them would be wrong about what
            // is in the working tree. On every other path the ledger gained nothing and this adds
            // nothing.
            recordNewFiles(context, before);
        }
    }

    /** Files this attempt added to the toolbox's ledger, named relative to the work directory. */
    private void recordNewFiles(Context context, Set<Path> before) {
        Path workDir = remediator.workDir();
        for (Path written : remediator.filesWritten()) {
            if (!before.contains(written)) {
                Path named = workDir == null ? written : workDir.relativize(written);
                context.addFileChanged(named.toString().replace('\\', '/'));
            }
        }
    }
}
