package com.example.securityharness.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ToolboxTest {

    /** Records the calls it receives so dispatch can be observed without side effects. */
    static class RecordingTool implements Tool {
        final List<String> calls = new ArrayList<>();
        private final String name;
        private final boolean readOnly;

        RecordingTool(String name) {
            this(name, false);
        }

        RecordingTool(String name, boolean readOnly) {
            this.name = name;
            this.readOnly = readOnly;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public boolean readOnly() {
            return readOnly;
        }

        @Override
        public ToolResult execute(ToolCall toolCall) {
            calls.add(toolCall.filePath());
            Path path = Path.of(toolCall.filePath()).toAbsolutePath();
            return readOnly ? ToolResult.readFrom(path, "content") : ToolResult.wrote(path);
        }
    }

    @Test
    void aReadIsRecordedAsReadAndNeverAsWritten() {
        Toolbox toolbox = new Toolbox(List.of(new RecordingTool("readFile", true)));

        ToolResult result = toolbox.call(new ToolCall("readFile", "pom.xml", null));

        assertEquals("content", result.output());
        assertEquals(Set.of(Path.of("pom.xml").toAbsolutePath()), toolbox.filesRead());
        assertEquals(Set.of(), toolbox.filesWritten());
    }

    @Test
    void aWriteIsRecordedAsWrittenAndNeverAsRead() {
        Toolbox toolbox = new Toolbox(List.of(new RecordingTool("writeFile")));

        toolbox.call(new ToolCall("writeFile", "pom.xml", "<project/>"));

        assertEquals(Set.of(Path.of("pom.xml").toAbsolutePath()), toolbox.filesWritten());
        assertEquals(Set.of(), toolbox.filesRead());
    }

    @Test
    void anUnknownToolIsNotReadOnlySoItStillReportsItself() {
        Toolbox toolbox = new Toolbox(List.of(new RecordingTool("writeFile")));

        assertFalse(toolbox.isReadOnly(new ToolCall("deleteFile", "pom.xml", null)));
        assertThrows(IllegalArgumentException.class,
                () -> toolbox.call(new ToolCall("deleteFile", "pom.xml", null)));
    }

    @Test
    void theDefaultToolboxHoldsExactlyTheToolsTheHarnessImplements(@TempDir Path workDir) {
        assertEquals(List.of("writeFile", "write", "readFile"),
                List.copyOf(new Toolbox(workDir).names()));
    }

    @Test
    void theDefaultToolboxActuallyWrites(@TempDir Path workDir) {
        new Toolbox(workDir).call(new ToolCall("writeFile", "pom.xml", "<project/>"));

        assertTrue(Files.isRegularFile(workDir.resolve("pom.xml")));
    }

    @Test
    void dispatchesToTheToolNamedByTheCall() {
        RecordingTool writeFile = new RecordingTool("writeFile");
        RecordingTool readFile = new RecordingTool("readFile");

        new Toolbox(List.of(writeFile, readFile)).call(new ToolCall("readFile", "pom.xml", null));

        assertEquals(List.of("pom.xml"), readFile.calls);
        assertEquals(List.of(), writeFile.calls);
    }

    @Test
    void remembersEveryPathItWrote(@TempDir Path workDir) {
        Toolbox toolbox = new Toolbox(workDir);

        toolbox.call(new ToolCall("writeFile", "pom.xml", "<project/>"));
        toolbox.call(new ToolCall("writeFile", "src/app.properties", "a=b"));

        assertEquals(List.of(workDir.resolve("pom.xml"), workDir.resolve("src/app.properties")),
                List.copyOf(toolbox.filesWritten()));
    }

    @Test
    void aFileWrittenTwiceIsDeclaredOnce(@TempDir Path workDir) {
        Toolbox toolbox = new Toolbox(workDir);

        toolbox.call(new ToolCall("write", "pom.xml", "<!-- CVE-1 fixed -->"));
        toolbox.call(new ToolCall("write", "pom.xml", "<!-- CVE-2 fixed -->"));

        assertEquals(List.of(workDir.resolve("pom.xml")), List.copyOf(toolbox.filesWritten()),
                "git reports one changed file, so a retry must not declare two");
    }

    @Test
    void aWriteThatThrewIsNotDeclared(@TempDir Path workDir) {
        Toolbox toolbox = new Toolbox(workDir);

        assertThrows(IllegalArgumentException.class,
                () -> toolbox.call(new ToolCall("writeFile", "../escaped.xml", "<project/>")));
        assertEquals(List.of(), List.copyOf(toolbox.filesWritten()));
    }

    @Test
    void aToolThatIsNotThereIsRejectedAndSaysWhatIsAvailable() {
        Toolbox toolbox = new Toolbox(List.of(new RecordingTool("writeFile")));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> toolbox.call(new ToolCall("runCommand", "mvn -q compile", null)));
        assertTrue(ex.getMessage().contains("runCommand"), ex.getMessage());
        assertTrue(ex.getMessage().contains("writeFile"), "the error should name what IS available: " + ex.getMessage());
    }
}
