package com.example.securityharness.agent;

import java.nio.file.Path;

public record ToolResult(Path written, Path read, String output) {

    public static ToolResult wrote(Path written) {
        return new ToolResult(written, null, null);
    }

    public static ToolResult readFrom(Path read, String output) {
        return new ToolResult(null, read, output);
    }
}
