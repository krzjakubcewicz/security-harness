package com.example.securityharness.agent;

public interface Tool {

    String name();

    ToolResult execute(ToolCall toolCall);

    /**
     * True when the tool only reads. Every read in one agent response runs before any write in it,
     * so a refusal that only a read could trigger still leaves the work directory untouched.
     */
    default boolean readOnly() {
        return false;
    }
}
