package com.example.securityharness.agent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Writes the file the agent asked for, replacing whatever was there. Paths are confined to the
 * work directory by WorkDirPaths.
 */
public class WriteFileTool implements Tool {
    private static final Logger log = LoggerFactory.getLogger(WriteFileTool.class);

    private final WorkDirPaths paths;

    public WriteFileTool(Path workDir) {
        this.paths = new WorkDirPaths(workDir);
    }

    @Override
    public String name() {
        return "writeFile";
    }

    @Override
    public ToolResult execute(ToolCall toolCall) {
        Path target = paths.guarded(toolCall.filePath());
        try {
            Files.createDirectories(target.getParent());
            Files.writeString(target, toolCall.content(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not write " + target, e);
        }
        log.info("      wrote {}", target);
        return ToolResult.wrote(target);
    }
}
