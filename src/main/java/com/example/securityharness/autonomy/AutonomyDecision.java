package com.example.securityharness.autonomy;

/**
 * What the harness decided to do with one service's changes. {@code rule} is null when no gate
 * matched - the default - and {@code finding} is null when there were no findings to judge. The
 * reason is for whoever reads the report later, and says which facts produced the action.
 * {@code warning} is null unless some finding in the service needs saying out loud on the pull
 * request itself, whichever finding ended up deciding the action.
 */
public record AutonomyDecision(String rule, AutonomyAction action, String finding, String reason,
                               String warning) {

    /** The common case: a decision with nothing to flag on top of what it already says. */
    public AutonomyDecision(String rule, AutonomyAction action, String finding, String reason) {
        this(rule, action, finding, reason, null);
    }

    /** The same decision, carrying something whoever reviews the changes has to be told. */
    AutonomyDecision warnedBy(String warning) {
        return new AutonomyDecision(rule, action, finding, reason, warning);
    }

    /** A service the gates had nothing to say about: an empty policy, or no findings at all. */
    static AutonomyDecision nothingToDo() {
        return new AutonomyDecision(null, AutonomyAction.NONE, null, "nothing to decide");
    }
}
