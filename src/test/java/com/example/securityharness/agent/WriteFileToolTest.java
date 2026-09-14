package com.example.securityharness.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class WriteFileToolTest {

    @Test
    void itAnswersToTheNameTheStubUses() {
        assertEquals("writeFile", new WriteFileTool(Path.of(".")).name());
    }

    @Test
    void writesTheContentToThePathRelativeToTheWorkDirectory(@TempDir Path workDir) throws Exception {
        new WriteFileTool(workDir).execute(new ToolCall("writeFile", "pom.xml", "<project/>"));

        assertEquals("<project/>", Files.readString(workDir.resolve("pom.xml"), StandardCharsets.UTF_8));
    }

    @Test
    void createsMissingParentDirectories(@TempDir Path workDir) throws Exception {
        new WriteFileTool(workDir).execute(new ToolCall("writeFile", "src/main/app.properties", "a=1"));

        assertTrue(Files.isRegularFile(workDir.resolve("src/main/app.properties")));
    }

    @Test
    void refusesAPathThatEscapesTheWorkDirectory(@TempDir Path workDir) {
        WriteFileTool tool = new WriteFileTool(workDir);

        assertThrows(IllegalArgumentException.class,
                () -> tool.execute(new ToolCall("writeFile", "../escaped.xml", "body")));
        assertFalse(Files.exists(workDir.getParent().resolve("escaped.xml")));
    }

    @Test
    void refusesAMissingPath(@TempDir Path workDir) {
        WriteFileTool tool = new WriteFileTool(workDir);

        assertThrows(IllegalArgumentException.class,
                () -> tool.execute(new ToolCall("writeFile", null, "body")));
        assertThrows(IllegalArgumentException.class,
                () -> tool.execute(new ToolCall("writeFile", "  ", "body")));
    }

    @Test
    void refusesToOverwriteADirectory(@TempDir Path workDir) throws Exception {
        Files.createDirectory(workDir.resolve("src"));
        WriteFileTool tool = new WriteFileTool(workDir);

        assertThrows(IllegalArgumentException.class,
                () -> tool.execute(new ToolCall("writeFile", "src", "body")));
    }

    @Test
    void refusesAPathThatLeavesTheWorkDirectoryThroughASymlinkedDirectory(@TempDir Path tempDir) throws Exception {
        Path workDir = Files.createDirectory(tempDir.resolve("work"));
        Path outside = Files.createDirectory(tempDir.resolve("outside"));
        assumeSymlinks(() -> Files.createSymbolicLink(workDir.resolve("escape"), outside));
        WriteFileTool tool = new WriteFileTool(workDir);

        assertThrows(IllegalArgumentException.class,
                () -> tool.execute(new ToolCall("writeFile", "escape/pom.xml", "body")));
        assertFalse(Files.exists(outside.resolve("pom.xml")));
    }

    @Test
    void refusesToWriteThroughAnExistingSymlink(@TempDir Path tempDir) throws Exception {
        Path workDir = Files.createDirectory(tempDir.resolve("work"));
        Path outside = Files.writeString(tempDir.resolve("outside.xml"), "original", StandardCharsets.UTF_8);
        assumeSymlinks(() -> Files.createSymbolicLink(workDir.resolve("pom.xml"), outside));
        WriteFileTool tool = new WriteFileTool(workDir);

        assertThrows(IllegalArgumentException.class,
                () -> tool.execute(new ToolCall("writeFile", "pom.xml", "body")));
        assertEquals("original", Files.readString(outside, StandardCharsets.UTF_8));
    }

    /** Creating symlinks needs a privilege this machine may not grant; skip rather than fail there. */
    private static void assumeSymlinks(ThrowingRunnable createLink) {
        try {
            createLink.run();
        } catch (IOException | UnsupportedOperationException e) {
            assumeTrue(false, "symlinks not available here: " + e.getMessage());
        }
    }

    private interface ThrowingRunnable {
        void run() throws IOException;
    }
}
