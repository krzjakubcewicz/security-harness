package com.example.securityharness.autonomy;

/**
 * What the harness does with a service's changes once it has finished making them. Declaration
 * order is the escalation order, from merging without asking anyone to filing a ticket instead
 * of a pull request.
 */
public enum AutonomyAction {
    AUTO_MERGE,
    PULL_REQUEST,
    SLACK,
    JIRA,
    /** No demand at all - a finding that changed nothing asks for nothing. */
    NONE;

    /**
     * The less autonomous of the two, which is what one service with several findings gets: a
     * patch bump does not license a major framework change sharing its working tree.
     *
     * <p>NONE is the exception. It sits last only because it is not an escalation at all, so it
     * loses every comparison rather than winning them - one finding that changed nothing must not
     * silence a sibling that needs a ticket.
     */
    public AutonomyAction strictest(AutonomyAction other) {
        if (this == NONE) {
            return other;
        }
        if (other == NONE) {
            return this;
        }
        return compareTo(other) >= 0 ? this : other;
    }
}
