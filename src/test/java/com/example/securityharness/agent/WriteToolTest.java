package com.example.securityharness.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.xml.parsers.DocumentBuilderFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class WriteToolTest {

    private static final String EOL = System.lineSeparator();

    private static final String XML_DECLARATION = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";

    @Test
    void itAnswersToTheNameTheStubUses() {
        assertEquals("write", new WriteTool(Path.of(".")).name());
    }

    @Test
    void putsTheContentAboveWhatIsAlreadyInTheFile(@TempDir Path workDir) throws Exception {
        Files.writeString(workDir.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);

        new WriteTool(workDir).execute(new ToolCall("write", "pom.xml", "<!-- CVE-1 fixed -->"));

        assertEquals("<!-- CVE-1 fixed -->" + EOL + "<project/>",
                Files.readString(workDir.resolve("pom.xml"), StandardCharsets.UTF_8));
    }

    @Test
    void putsTheContentBelowALeadingXmlDeclaration(@TempDir Path workDir) throws Exception {
        // The declaration has to be the first thing in the file. Maven refuses to read a pom with
        // anything in front of it: "processing instruction can not have PITarget with reserved
        // xml name" - which is what a marker written above it used to produce.
        Files.writeString(workDir.resolve("pom.xml"),
                XML_DECLARATION + EOL + "<project/>", StandardCharsets.UTF_8);

        new WriteTool(workDir).execute(new ToolCall("write", "pom.xml", "<!-- CVE-1 fixed -->"));

        assertEquals(XML_DECLARATION + EOL + "<!-- CVE-1 fixed -->" + EOL + "<project/>",
                Files.readString(workDir.resolve("pom.xml"), StandardCharsets.UTF_8));
    }

    @Test
    void theMarkedFileIsStillWellFormedXml(@TempDir Path workDir) throws Exception {
        Files.writeString(workDir.resolve("pom.xml"),
                XML_DECLARATION + EOL + "<project><modelVersion>4.0.0</modelVersion></project>",
                StandardCharsets.UTF_8);

        new WriteTool(workDir).execute(new ToolCall("write", "pom.xml", "<!-- CVE-1 fixed -->"));

        // Parsing it is the assertion: this is the check the build gate's mvn run performs.
        DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(workDir.resolve("pom.xml").toFile());
    }

    @Test
    void keepsTheContentOffTheDeclarationsLineWhenNothingFollowsIt(@TempDir Path workDir) throws Exception {
        Files.writeString(workDir.resolve("pom.xml"), XML_DECLARATION, StandardCharsets.UTF_8);

        new WriteTool(workDir).execute(new ToolCall("write", "pom.xml", "<!-- CVE-1 fixed -->"));

        assertEquals(XML_DECLARATION + EOL + "<!-- CVE-1 fixed -->" + EOL,
                Files.readString(workDir.resolve("pom.xml"), StandardCharsets.UTF_8));
    }

    @Test
    void aDeclarationLookalikeInsideTheFileIsNotTreatedAsOne(@TempDir Path workDir) throws Exception {
        // Only a declaration at the very start is special; one further down is just text.
        Files.writeString(workDir.resolve("notes.txt"), "read me" + EOL + XML_DECLARATION, StandardCharsets.UTF_8);

        new WriteTool(workDir).execute(new ToolCall("write", "notes.txt", "first"));

        assertEquals("first" + EOL + "read me" + EOL + XML_DECLARATION,
                Files.readString(workDir.resolve("notes.txt"), StandardCharsets.UTF_8));
    }

    @Test
    void prependingTwiceLeavesBothLinesNewestFirst(@TempDir Path workDir) throws Exception {
        Files.writeString(workDir.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);
        WriteTool tool = new WriteTool(workDir);

        tool.execute(new ToolCall("write", "pom.xml", "<!-- CVE-1 fixed -->"));
        tool.execute(new ToolCall("write", "pom.xml", "<!-- CVE-2 fixed -->"));

        assertEquals("<!-- CVE-2 fixed -->" + EOL + "<!-- CVE-1 fixed -->" + EOL + "<project/>",
                Files.readString(workDir.resolve("pom.xml"), StandardCharsets.UTF_8));
    }

    @Test
    void createsTheFileWhenThereIsNothingToPrependOnto(@TempDir Path workDir) throws Exception {
        new WriteTool(workDir).execute(new ToolCall("write", "pom.xml", "<!-- CVE-1 fixed -->"));

        assertEquals("<!-- CVE-1 fixed -->" + EOL,
                Files.readString(workDir.resolve("pom.xml"), StandardCharsets.UTF_8));
    }

    @Test
    void createsMissingParentDirectories(@TempDir Path workDir) {
        new WriteTool(workDir).execute(new ToolCall("write", "src/main/app.properties", "a=1"));

        assertTrue(Files.isRegularFile(workDir.resolve("src/main/app.properties")));
    }

    @Test
    void refusesAPathThatEscapesTheWorkDirectory(@TempDir Path workDir) {
        WriteTool tool = new WriteTool(workDir);

        assertThrows(IllegalArgumentException.class,
                () -> tool.execute(new ToolCall("write", "../escaped.xml", "body")));
        assertFalse(Files.exists(workDir.getParent().resolve("escaped.xml")));
    }

    @Test
    void refusesAMissingPath(@TempDir Path workDir) {
        WriteTool tool = new WriteTool(workDir);

        assertThrows(IllegalArgumentException.class,
                () -> tool.execute(new ToolCall("write", null, "body")));
        assertThrows(IllegalArgumentException.class,
                () -> tool.execute(new ToolCall("write", "  ", "body")));
    }

    @Test
    void refusesToPrependToADirectory(@TempDir Path workDir) throws Exception {
        Files.createDirectory(workDir.resolve("src"));
        WriteTool tool = new WriteTool(workDir);

        assertThrows(IllegalArgumentException.class,
                () -> tool.execute(new ToolCall("write", "src", "body")));
    }

    @Test
    void refusesAPathThatLeavesTheWorkDirectoryThroughASymlinkedDirectory(@TempDir Path tempDir) throws Exception {
        Path workDir = Files.createDirectory(tempDir.resolve("work"));
        Path outside = Files.createDirectory(tempDir.resolve("outside"));
        assumeSymlinks(() -> Files.createSymbolicLink(workDir.resolve("escape"), outside));
        WriteTool tool = new WriteTool(workDir);

        assertThrows(IllegalArgumentException.class,
                () -> tool.execute(new ToolCall("write", "escape/pom.xml", "body")));
        assertFalse(Files.exists(outside.resolve("pom.xml")));
    }

    @Test
    void refusesToPrependThroughAnExistingSymlink(@TempDir Path tempDir) throws Exception {
        Path workDir = Files.createDirectory(tempDir.resolve("work"));
        Path outside = Files.writeString(tempDir.resolve("outside.xml"), "original", StandardCharsets.UTF_8);
        assumeSymlinks(() -> Files.createSymbolicLink(workDir.resolve("pom.xml"), outside));
        WriteTool tool = new WriteTool(workDir);

        assertThrows(IllegalArgumentException.class,
                () -> tool.execute(new ToolCall("write", "pom.xml", "body")));
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
