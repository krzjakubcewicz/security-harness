package com.example.securityharness.autonomy;

import com.example.securityharness.buildgate.BuildGateResult;
import com.example.securityharness.remediation.FindingRecord;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Decides what happens to the changes a service's run produced. Every finding is judged against
 * the rules in autonomy.yaml, first match wins per finding, and the strictest of those answers is
 * the service's: one working tree becomes one branch, so the most cautious finding sets the terms.
 *
 * <p>Two deliberate differences from AgentGuards, whose dialect this shares. A finding that
 * matches nothing defaults to PULL_REQUEST rather than to "proceed" - an unanticipated change is
 * exactly the kind a person should read. And an empty rule list means the feature is not
 * configured at all, not a policy that permits everything.
 */
public class AutonomyGates {

    private static final Set<String> KNOWN_FIELDS = Set.of(
            "versionChange", "changeKind", "buildGate", "severity", "packageName", "service",
            "outcome");

    private final List<AutonomyRule> rules;

    public AutonomyGates(List<AutonomyRule> rules) {
        this.rules = List.copyOf(rules);
    }

    public AutonomyGates() {
        this(List.of());
    }

    /** False when no rules were configured: the harness then decides nothing and says nothing. */
    public boolean isConfigured() {
        return !rules.isEmpty();
    }

    /**
     * @param records        every finished finding, from Context.getRecords()
     * @param buildGate      the service's gate result, or null when it never reached the gate -
     *                       a rule matching on it then matches nothing
     * @param dependencyFile what the detected stack declares versions in, or null
     *
     * <p>Callers are expected to check {@link #isConfigured()} first. A null autonomy field on the
     * report means the caller skipped this because the feature is off; a NONE decision from here
     * means the caller called anyway and this is what an unconfigured instance answers. The two are
     * deliberately different signals - do not treat a NONE decision as equivalent to never asking.
     */
    public AutonomyDecision decide(String service, List<FindingRecord> records,
                                   BuildGateResult buildGate, String dependencyFile) {
        if (!isConfigured()) {
            return AutonomyDecision.nothingToDo();
        }
        AutonomyDecision winner = null;
        for (FindingRecord record : records) {
            AutonomyDecision candidate = decideOne(service, record, buildGate, dependencyFile);
            // Ties keep the earlier finding: strictest returns the winner when the actions match.
            if (winner == null || candidate.action().strictest(winner.action()) != winner.action()) {
                winner = candidate;
            }
        }
        if (winner == null) {
            return AutonomyDecision.nothingToDo();
        }
        String warning = warningFor(records);
        return warning == null ? winner : winner.warnedBy(warning);
    }

    /**
     * Said out loud whoever else won the decision. Strictest-wins names one finding, and on a
     * service where one finding lost tests and another blocked the build that finding is not this
     * one - but the lost tests are the fact a reviewer most needs on the pull request.
     */
    private static String warningFor(List<FindingRecord> records) {
        for (FindingRecord record : records) {
            if (record.testsBefore() != null && record.testsAfter() < record.testsBefore()) {
                return "TESTS LOST: " + record.id() + " left " + tests(record.testsAfter())
                        + " that will run where there were " + record.testsBefore()
                        + " - removed, disabled, or both";
            }
        }
        return null;
    }

    /** This sentence goes on a pull request, so "1 tests" is not good enough. */
    private static String tests(int count) {
        return count == 1 ? "1 test" : count + " tests";
    }

    private AutonomyDecision decideOne(String service, FindingRecord record,
                                       BuildGateResult buildGate, String dependencyFile) {
        String reason = reason(record, dependencyFile);
        for (AutonomyRule rule : rules) {
            if (matches(rule, service, record, buildGate, dependencyFile)) {
                return new AutonomyDecision(rule.name(), rule.action(), record.id(), reason);
            }
        }
        return new AutonomyDecision(null, AutonomyAction.PULL_REQUEST, record.id(), reason);
    }

    /** The facts the rules saw, spelled out, so the report explains itself without the rules. */
    private static String reason(FindingRecord record, String dependencyFile) {
        return record.id() + " " + record.packageName() + " "
                + record.installedVersion() + " -> " + record.fixedVersion()
                + " (" + VersionChange.between(record.installedVersion(), record.fixedVersion())
                + ", " + ChangeKind.of(record.filesChanged(), dependencyFile) + ")";
    }

    private boolean matches(AutonomyRule rule, String service, FindingRecord record,
                            BuildGateResult buildGate, String dependencyFile) {
        for (String field : rule.match().keySet()) {
            requireKnown(rule, field);
        }
        for (Map.Entry<String, Object> entry : rule.match().entrySet()) {
            Object actual = valueOf(rule, entry.getKey(), service, record, buildGate, dependencyFile);
            Object expected = entry.getValue();
            if (expected instanceof Map) {
                throw new IllegalArgumentException("Autonomy gate '" + rule.name() + "': '"
                        + entry.getKey() + "' does not support gt/lt comparisons - no gate field is"
                        + " numeric. Guards rules that compare numbers do not port over as-is.");
            }
            boolean matched = expected instanceof List<?> options
                    ? options.stream().anyMatch(option -> valueMatches(entry.getKey(), option, actual))
                    : valueMatches(entry.getKey(), expected, actual);
            if (!matched) {
                return false;
            }
        }
        return true;
    }

    private Object valueOf(AutonomyRule rule, String field, String service, FindingRecord record,
                           BuildGateResult buildGate, String dependencyFile) {
        return switch (field) {
            case "versionChange" -> VersionChange.between(record.installedVersion(), record.fixedVersion());
            case "changeKind" -> ChangeKind.of(record.filesChanged(), dependencyFile);
            case "buildGate" -> buildGate == null ? null : buildGate.action();
            case "severity" -> record.severity();
            case "packageName" -> record.packageName();
            case "service" -> service;
            case "outcome" -> record.outcome();
            default -> throw new IllegalStateException(field);
        };
    }

    /**
     * Every key is checked before any is evaluated: a typo has to fail the run, not quietly fail
     * to match because a hash order happened to reject an earlier key first.
     */
    private static void requireKnown(AutonomyRule rule, String field) {
        if (!KNOWN_FIELDS.contains(field)) {
            throw new IllegalArgumentException(
                    "Autonomy gate '" + rule.name() + "' matches on unknown field '" + field + "'");
        }
    }

    /**
     * Exact and case-insensitive, as every field is - except packageName, where '*' stands for any
     * run of characters, so one rule can cover a whole coordinate group. Only packageName: a group
     * is the one thing here that is named in parts, and guards.yaml does not glob at all.
     */
    private static boolean valueMatches(String field, Object expected, Object actual) {
        String pattern = String.valueOf(expected);
        if (!field.equals("packageName") || pattern.indexOf('*') < 0) {
            return equalsIgnoreCase(expected, actual);
        }
        return actual != null && glob(pattern).matcher(String.valueOf(actual)).matches();
    }

    /**
     * The whole name has to match, not part of it: 'spring-core' stays the exact name it reads as,
     * and a pattern reaches further than itself only where somebody wrote a star.
     */
    private static Pattern glob(String pattern) {
        return Pattern.compile(Arrays.stream(pattern.split("\\*", -1))
                .map(Pattern::quote).collect(Collectors.joining(".*")), Pattern.CASE_INSENSITIVE);
    }

    /** A null actual never matches, so a rule about a fact the run does not have cannot fire. */
    private static boolean equalsIgnoreCase(Object expected, Object actual) {
        return actual != null && String.valueOf(expected).equalsIgnoreCase(String.valueOf(actual));
    }
}
