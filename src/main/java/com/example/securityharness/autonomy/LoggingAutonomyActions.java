package com.example.securityharness.autonomy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoggingAutonomyActions implements AutonomyActions {
    private static final Logger log = LoggerFactory.getLogger(LoggingAutonomyActions.class);

    @Override
    public void perform(String service, AutonomyDecision decision) {
        log.info("    {} [{}]", describe(service, decision), decision.reason());
        String alarm = alarm(decision);
        if (alarm != null) {
            // Its own line, and loud: this is what the pipeline lifts onto the pull request, and
            // it is the reason somebody should read the diff rather than skim the title.
            log.warn("    {}", alarm);
        }
    }

    /** What the pull request has to say beyond which action it is, or null when there is nothing. */
    static String alarm(AutonomyDecision decision) {
        return decision.warning() == null ? null : "!! " + decision.warning();
    }

    /** Always starts with "would": nothing here has happened. */
    static String describe(String service, AutonomyDecision decision) {
        return switch (decision.action()) {
            case AUTO_MERGE -> "would open a pull request for " + service + " and merge it";
            case PULL_REQUEST -> "would open a pull request for " + service + " and wait for review";
            case SLACK -> "would post to the Slack channel about " + service;
            case JIRA -> "would create a Jira ticket for " + service;
            case NONE -> "would do nothing for " + service;
        };
    }
}
