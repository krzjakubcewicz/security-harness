package com.example.securityharness.agent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WriteTool implements Tool {
    private static final Logger log = LoggerFactory.getLogger(WriteTool.class);

    /** A leading XML declaration and the line break after it, if the file opens with one. */
    private static final Pattern XML_DECLARATION = Pattern.compile("\\A<\\?xml[^>]*\\?>\\R?");

    private final WorkDirPaths paths;

    public WriteTool(Path workDir) {
        this.paths = new WorkDirPaths(workDir);
    }

    @Override
    public String name() {
        return "write";
    }

    @Override
    public ToolResult execute(ToolCall toolCall) {
        Path target = paths.guarded(toolCall.filePath());
        try {
            String existing = Files.isRegularFile(target)
                    ? Files.readString(target, StandardCharsets.UTF_8)
                    : "";
            Files.createDirectories(target.getParent());
            Files.writeString(target, prepended(existing, toolCall.content()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not prepend to " + target, e);
        }
        log.info("      prepended to {}", target);
        return ToolResult.wrote(target);
    }

    /** {@code content} on its own line, after any XML declaration and before everything else. */
    private static String prepended(String existing, String content) {
        Matcher declaration = XML_DECLARATION.matcher(existing);
        int insertAt = declaration.lookingAt() ? declaration.end() : 0;
        String head = existing.substring(0, insertAt);
        if (!head.isEmpty() && !head.endsWith("\n")) {
            // A declaration with nothing after it: keep the content off the same line.
            head = head + System.lineSeparator();
        }
        return head + content + System.lineSeparator() + existing.substring(insertAt);
    }
}
