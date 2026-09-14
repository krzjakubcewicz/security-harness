package com.example.securityharness.stack;

import com.example.securityharness.buildgate.BuildGateConfiguration.StackGate;
import com.example.securityharness.buildgate.BuildGateStep;
import com.example.securityharness.policy.Verdict;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StackDetectorTest {

    static Map<String, StackGate> javaAndPython() {
        Map<String, StackGate> stacks = new LinkedHashMap<>();
        stacks.put("java", new StackGate("pom.xml", "pom.xml",
                List.of(new BuildGateStep("compile", "exit 0", Verdict.BLOCK))));
        stacks.put("python", new StackGate("pyproject.toml", "requirements.lock",
                List.of(new BuildGateStep("test", "exit 0", Verdict.BLOCK))));
        return stacks;
    }

    static void marker(Path directory, String name) throws IOException {
        Files.writeString(directory.resolve(name), "");
    }

    @Test
    void aPomMakesItAJavaService(@TempDir Path tempDir) throws IOException {
        marker(tempDir, "pom.xml");

        assertEquals(List.of("java"), new StackDetector(javaAndPython(), tempDir).detect());
    }

    @Test
    void aPyprojectMakesItAPythonService(@TempDir Path tempDir) throws IOException {
        marker(tempDir, "pyproject.toml");

        assertEquals(List.of("python"), new StackDetector(javaAndPython(), tempDir).detect());
    }

    @Test
    void bothMarkersReportBothStacksInConfigOrder(@TempDir Path tempDir) throws IOException {
        marker(tempDir, "pyproject.toml");
        marker(tempDir, "pom.xml");

        assertEquals(List.of("java", "python"), new StackDetector(javaAndPython(), tempDir).detect(),
                "config order, not the order the files happened to be created in");
    }

    @Test
    void noMarkerDetectsNothing(@TempDir Path tempDir) {
        assertEquals(List.of(), new StackDetector(javaAndPython(), tempDir).detect());
    }

    @Test
    void aMarkerInASubdirectoryDoesNotCount(@TempDir Path tempDir) throws IOException {
        Files.createDirectory(tempDir.resolve("nested"));
        marker(tempDir.resolve("nested"), "pom.xml");

        assertEquals(List.of(), new StackDetector(javaAndPython(), tempDir).detect(),
                "the marker has to sit at the top of the service directory");
    }

    @Test
    void aDirectoryThatDoesNotExistDetectsNothing() {
        Path missing = Path.of("this-directory-does-not-exist-" + System.nanoTime());

        assertEquals(List.of(), new StackDetector(javaAndPython(), missing).detect());
    }

    @Test
    void oneDetectedStackNamesItsDependencyFile(@TempDir Path tempDir) {
        StackDetector detector = new StackDetector(javaAndPython(), tempDir);

        assertEquals("pom.xml", detector.dependencyFile(List.of("java")));
        assertEquals("requirements.lock", detector.dependencyFile(List.of("python")));
    }

    @Test
    void aPolyglotServiceNamesNoDependencyFile(@TempDir Path tempDir) {
        StackDetector detector = new StackDetector(javaAndPython(), tempDir);

        assertNull(detector.dependencyFile(List.of("java", "python")),
                "two dependency files, and the stack alone cannot say which a package is in");
    }

    @Test
    void anUndetectedServiceNamesNoDependencyFile(@TempDir Path tempDir) {
        assertNull(new StackDetector(javaAndPython(), tempDir).dependencyFile(List.of()));
    }

    @Test
    void aStackThatDeclaresNoDependencyFileNamesNone(@TempDir Path tempDir) {
        Map<String, StackGate> stacks = Map.of("go",
                new StackGate("go.mod", List.of(new BuildGateStep("build", "exit 0", Verdict.BLOCK))));

        assertNull(new StackDetector(stacks, tempDir).dependencyFile(List.of("go")));
    }

    @Test
    void anUnknownStackNameNamesNoDependencyFile(@TempDir Path tempDir) {
        assertNull(new StackDetector(javaAndPython(), tempDir).dependencyFile(List.of("rust")),
                "an unconfigured name must not blow up the run");
    }

    @Test
    void aDetectorWithStacksIsConfigured(@TempDir Path tempDir) {
        assertTrue(new StackDetector(javaAndPython(), tempDir).isConfigured());
    }

    @Test
    void noneIsNotConfiguredAndDetectsNothing() {
        StackDetector detector = StackDetector.none();

        assertFalse(detector.isConfigured());
        assertEquals(List.of(), detector.detect());
    }

    @Test
    void markerNamesAreWhatDetectionLookedFor(@TempDir Path tempDir) {
        assertEquals(List.of("pom.xml", "pyproject.toml"),
                new StackDetector(javaAndPython(), tempDir).markerNames());
    }
}
