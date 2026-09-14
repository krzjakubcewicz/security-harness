package com.example.securityharness.agent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Hands the agent a file from the work directory, framed as untrusted data by UntrustedContent.
 * Paths are confined to the work directory by WorkDirPaths, the same as every writing tool.
 *
 * <p>Everything here is refusal or I/O; what may be said about the bytes is UntrustedContent's
 * job. Two refusals belong to this layer because only this layer sees bytes: content that is not
 * UTF-8, and content carrying NUL - neither is source, and both are ways to smuggle characters
 * past a text-shaped defence.
 */
public class ReadFileTool implements Tool {
    private static final Logger log = LoggerFactory.getLogger(ReadFileTool.class);

    private final WorkDirPaths paths;

    public ReadFileTool(Path workDir) {
        this.paths = new WorkDirPaths(workDir);
    }

    @Override
    public String name() {
        return "readFile";
    }

    @Override
    public boolean readOnly() {
        return true;
    }

    @Override
    public ToolResult execute(ToolCall toolCall) {
        Path target = paths.guarded(toolCall.filePath());
        if (!Files.isRegularFile(target)) {
            throw new IllegalArgumentException("Tool call target does not exist: " + toolCall.filePath());
        }
        String output = UntrustedContent.wrapped(
                toolCall.filePath(), text(target, toolCall.filePath()), size(target));
        // The content itself is never logged: it is the untrusted half of the run, and a log is
        // read by people and by whatever ships logs onward.
        log.info("      read {} ({} characters handed back)", target, output.length());
        return ToolResult.readFrom(target, output);
    }

    /**
     * At most one character past the cap, so the caller can tell "exactly full" from "there is
     * more" without the file's size deciding how much memory this takes.
     */
    private static String text(Path target, String filePath) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        char[] buffer = new char[UntrustedContent.MAX_CHARACTERS + 1];
        int filled = 0;
        try (Reader reader = new InputStreamReader(Files.newInputStream(target), decoder)) {
            int read;
            while (filled < buffer.length
                    && (read = reader.read(buffer, filled, buffer.length - filled)) != -1) {
                filled += read;
            }
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Tool call target is not UTF-8 text: " + filePath);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + target, e);
        }
        String text = new String(buffer, 0, filled);
        if (text.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("Tool call target is not text: " + filePath);
        }
        return text;
    }

    private static long size(Path target) {
        try {
            return Files.size(target);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not size " + target, e);
        }
    }
}
