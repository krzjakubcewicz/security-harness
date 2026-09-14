package com.example.securityharness.guards;

import com.example.securityharness.agent.ToolCall;
import com.example.securityharness.policy.Verdict;

public class GuardViolation extends RuntimeException {

    private final String ruleName;
    private final Verdict action;
    private final ToolCall toolCall;

    public GuardViolation(String ruleName, Verdict action, ToolCall toolCall) {
        this(ruleName, action, toolCall,
                "Guard '" + ruleName + "' refused " + toolCall.tool() + " " + toolCall.filePath()
                        + " (" + action + ")");
    }

    /**
     * For a subclass whose own message is not "refused". Not every violation is a refusal: a check
     * that can only run once the writes have landed has not stopped anything, and saying it did
     * would mislead whoever reads the run.
     */
    protected GuardViolation(String ruleName, Verdict action, ToolCall toolCall, String message) {
        super(message);
        this.ruleName = ruleName;
        this.action = action;
        this.toolCall = toolCall;
    }

    public String ruleName() {
        return ruleName;
    }

    public Verdict action() {
        return action;
    }

    public ToolCall toolCall() {
        return toolCall;
    }
}
