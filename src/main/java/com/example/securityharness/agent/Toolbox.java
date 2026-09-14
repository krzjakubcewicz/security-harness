package com.example.securityharness.agent;

import com.example.securityharness.remediation.Remediator;
import com.example.securityharness.remediation.Workflow;
import com.example.securityharness.verify.ChangeVerifier;

import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Everything the agent is allowed to do, keyed by tool name. A call naming a tool that is
 * not in here is a programming error, not a remediation outcome: it stops the whole run
 * (Workflow.run catches the RuntimeException and ends in FAILED).
 *
 * <p>It is also the harness's record of what the agent changed: every successful call is
 * remembered in {@link #filesWritten()}, which ChangeVerifier compares against git. One
 * toolbox lives as long as one service's Remediator, so that record needs no resetting.
 */
public class Toolbox {

    private final Map<String, Tool> tools;

    /** Every path a tool wrote, in call order. A set, so re-writing a file counts once. */
    private final Set<Path> filesWritten = new LinkedHashSet<>();

    /** Every path a tool read, in call order. Audit only: a read changes nothing to verify. */
    private final Set<Path> filesRead = new LinkedHashSet<>();

    /** Every tool the harness currently implements, rooted at workDir. */
    public Toolbox(Path workDir) {
        this(List.of(new WriteFileTool(workDir), new WriteTool(workDir), new ReadFileTool(workDir)));
    }

    public Toolbox(List<Tool> tools) {
        Map<String, Tool> byName = new LinkedHashMap<>();
        for (Tool tool : tools) {
            byName.put(tool.name(), tool);
        }
        this.tools = Collections.unmodifiableMap(byName);
    }

    /** Runs the call and returns what the tool did, recording the path in the matching ledger. */
    public ToolResult call(ToolCall toolCall) {
        Tool tool = tools.get(toolCall.tool());
        if (tool == null) {
            throw new IllegalArgumentException(
                    "Unsupported tool: " + toolCall.tool() + " (available: " + names() + ")");
        }
        ToolResult result = tool.execute(toolCall);
        // Only after execute returns: a call that threw left nothing to declare.
        if (result.written() != null) {
            filesWritten.add(result.written());
        }
        if (result.read() != null) {
            filesRead.add(result.read());
        }
        return result;
    }

    /** True when this call's tool only reads. An unknown tool is not read-only - call() reports it. */
    public boolean isReadOnly(ToolCall toolCall) {
        Tool tool = tools.get(toolCall.tool());
        return tool != null && tool.readOnly();
    }

    /** The tool names this toolbox answers to, in registration order. */
    public Set<String> names() {
        return tools.keySet();
    }

    /** Every path this toolbox has written, each once, in the order first written. */
    public Set<Path> filesWritten() {
        return Collections.unmodifiableSet(filesWritten);
    }

    /** Every path this toolbox has read, each once, in the order first read. */
    public Set<Path> filesRead() {
        return Collections.unmodifiableSet(filesRead);
    }
}
