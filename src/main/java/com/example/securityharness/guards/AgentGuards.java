package com.example.securityharness.guards;

import com.example.securityharness.agent.ToolCall;
import com.example.securityharness.findings.Finding;
import com.example.securityharness.policy.Verdict;
import com.example.securityharness.remediation.Context;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Gates the AGENT_REMEDIATION strategy only. First matching rule wins; no match allows.
 */
public class AgentGuards {

    private static final Set<String> KNOWN_FIELDS = Set.of(
            "severity", "cve", "packageName", "service", "installedVersion",
            "fixedVersion", "slaDaysRemaining", "attempt", "maxAttempts", "verifyPassed",
            "pathSegment");

    private final List<GuardRule> rules;

    public AgentGuards(List<GuardRule> rules) {
        this.rules = List.copyOf(rules);
    }

    public AgentGuards() {
        this(List.of());
    }

    public Verdict evaluateBefore(Finding finding, Context context) {
        return actionOf(matchingBeforeRule(finding, context));
    }

    public Verdict evaluateAfter(Finding finding, Context context) {
        return actionOf(matchingAfterRule(finding, context));
    }

    /** The first 'when: before' rule this finding trips, or null when nothing matched. */
    public GuardRule matchingBeforeRule(Finding finding, Context context) {
        return firstMatch(GuardRule.When.BEFORE, finding, context, false, null);
    }

    /** The first 'when: after' rule this finding trips, or null when nothing matched. */
    public GuardRule matchingAfterRule(Finding finding, Context context) {
        return firstMatch(GuardRule.When.AFTER, finding, context, true, null);
    }

    /** No rule matched means allow. */
    public static Verdict actionOf(GuardRule matched) {
        return matched == null ? Verdict.ALLOW : matched.action();
    }

    /**
     * The first 'when: tool' rule this call trips, or null when it is allowed. Returns the rule
     * rather than the action so the caller can name it in the refusal. The tool layer has no
     * Context, so a tool rule cannot match on attempt or maxAttempts.
     */
    public GuardRule matchingToolRule(ToolCall toolCall, Finding finding) {
        return firstMatch(GuardRule.When.TOOL, finding, null, false, toolCall);
    }

    private GuardRule firstMatch(GuardRule.When when, Finding finding, Context context,
                                 boolean verifyPassed, ToolCall toolCall) {
        for (GuardRule rule : rules) {
            if (rule.when() == when && matches(rule, finding, context, verifyPassed, toolCall)) {
                return rule;
            }
        }
        return null;
    }

    private boolean matches(GuardRule rule, Finding finding, Context context,
                            boolean verifyPassed, ToolCall toolCall) {
        for (Map.Entry<String, Object> entry : rule.match().entrySet()) {
            if (!fieldMatches(rule, entry.getKey(), entry.getValue(), finding, context, verifyPassed, toolCall)) {
                return false;
            }
        }
        return true;
    }

    private boolean fieldMatches(GuardRule rule, String field, Object expected, Finding finding,
                                 Context context, boolean verifyPassed, ToolCall toolCall) {
        if (!KNOWN_FIELDS.contains(field)) {
            throw new IllegalArgumentException("Guard '" + rule.name() + "' matches on unknown field '" + field + "'");
        }
        if (field.equals("pathSegment")) {
            return pathSegmentMatches(rule, expected, toolCall);
        }
        Object actual = fieldValue(rule, field, finding, context, verifyPassed);
        if (expected instanceof Map<?, ?> ops) {
            return compare(rule, field, ops, actual);
        }
        if (expected instanceof List<?> options) {
            return options.stream().anyMatch(v -> equalsIgnoreCase(v, actual));
        }
        return equalsIgnoreCase(expected, actual);
    }

    private Object fieldValue(GuardRule rule, String field, Finding finding,
                             Context context, boolean verifyPassed) {
        return switch (field) {
            case "severity" -> finding.severity();
            case "cve" -> finding.cve();
            case "packageName" -> finding.packageName();
            case "service" -> finding.service();
            case "installedVersion" -> finding.installedVersion();
            case "fixedVersion" -> finding.fixedVersion();
            case "slaDaysRemaining" -> finding.slaDaysRemaining();
            case "attempt" -> requireContext(rule, field, context).getAttempt();
            case "maxAttempts" -> requireContext(rule, field, context).getMaxAttempts();
            case "verifyPassed" -> verifyPassed;
            default -> throw new IllegalStateException(field);
        };
    }

    private Context requireContext(GuardRule rule, String field, Context context) {
        if (context == null) {
            throw new IllegalArgumentException(
                    "Guard '" + rule.name() + "': '" + field + "' is not available to a 'when: tool' rule");
        }
        return context;
    }

    /**
     * True when any single segment of the tool call's path equals the expected value, or one of
     * them when a list is given. Segment equality, so '.gitignore' is not '.git'.
     */
    private boolean pathSegmentMatches(GuardRule rule, Object expected, ToolCall toolCall) {
        if (toolCall == null) {
            throw new IllegalArgumentException(
                    "Guard '" + rule.name() + "': 'pathSegment' only matches on a 'when: tool' rule");
        }
        if (toolCall.filePath() == null || toolCall.filePath().isBlank()) {
            return false;
        }
        List<?> options = expected instanceof List<?> list ? list : List.of(expected);
        for (Path segment : Path.of(toolCall.filePath()).normalize()) {
            if (options.stream().anyMatch(option -> equalsIgnoreCase(option, segment.toString()))) {
                return true;
            }
        }
        return false;
    }

    private boolean compare(GuardRule rule, String field, Map<?, ?> ops, Object actual) {
        if (!(actual instanceof Number actualNumber)) {
            throw new IllegalArgumentException(
                    "Guard '" + rule.name() + "': '" + field + "' is not numeric, cannot use gt/gte/lt/lte");
        }
        double a = actualNumber.doubleValue();
        for (Map.Entry<?, ?> op : ops.entrySet()) {
            double n = ((Number) op.getValue()).doubleValue();
            boolean ok = switch (op.getKey().toString()) {
                case "gt" -> a > n;
                case "gte" -> a >= n;
                case "lt" -> a < n;
                case "lte" -> a <= n;
                default -> throw new IllegalArgumentException(
                        "Guard '" + rule.name() + "': unknown comparison '" + op.getKey() + "'");
            };
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private boolean equalsIgnoreCase(Object expected, Object actual) {
        return actual != null && String.valueOf(expected).equalsIgnoreCase(String.valueOf(actual));
    }
}
