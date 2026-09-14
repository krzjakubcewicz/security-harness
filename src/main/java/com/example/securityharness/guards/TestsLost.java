package com.example.securityharness.guards;

import com.example.securityharness.agent.ToolCall;
import com.example.securityharness.policy.Verdict;

public class TestsLost extends GuardViolation {

    private final int before;
    private final int after;

    public TestsLost(String ruleName, ToolCall toolCall, int before, int after) {
        super(ruleName, Verdict.MANUAL_REVIEW, toolCall,
                ruleName + ": " + before + " tests would have run before, " + after + " after"
                        + " - " + toolCall.tool() + " " + toolCall.filePath()
                        + " (" + Verdict.MANUAL_REVIEW + ")");
        this.before = before;
        this.after = after;
    }

    /** Tests that would have run across the files this response wrote, before it wrote them. */
    public int before() {
        return before;
    }

    /** Tests that will run across those same files now. Always less than {@link #before()}. */
    public int after() {
        return after;
    }
}
