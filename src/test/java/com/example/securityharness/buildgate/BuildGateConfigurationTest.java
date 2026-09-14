package com.example.securityharness.buildgate;

import com.example.securityharness.buildgate.BuildGateConfiguration.StackGate;
import com.example.securityharness.config.ConfigLoadException;
import com.example.securityharness.config.ConfigLoader;
import com.example.securityharness.policy.Verdict;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BuildGateConfigurationTest {

    @Test
    void loadsStepsInOrder(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("build-gate.yaml");
        Files.writeString(file, """
                stacks:
                  java:
                    marker: pom.xml
                    steps:
                      - name: compile
                        command: mvn -q compile
                        onFailure: block
                      - name: test
                        command: mvn -q test
                        onFailure: manual_review
                """);

        List<BuildGateStep> steps = ConfigLoader.yaml().load(file, BuildGateConfiguration.class).stacks().get("java").steps();

        assertEquals(2, steps.size());
        assertEquals(new BuildGateStep("compile", "mvn -q compile", Verdict.BLOCK), steps.get(0));
        assertEquals(new BuildGateStep("test", "mvn -q test", Verdict.MANUAL_REVIEW), steps.get(1));
    }

    @Test
    void loadsStacksInDeclarationOrderWithTheirMarkers(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("build-gate.yaml");
        Files.writeString(file, """
                stacks:
                  java:
                    marker: pom.xml
                    steps:
                      - name: test
                        command: mvn -q test
                        onFailure: block
                  python:
                    marker: pyproject.toml
                    steps:
                      - name: test
                        command: python -m pytest -q
                        onFailure: block
                """);

        Map<String, StackGate> stacks = ConfigLoader.yaml().load(file, BuildGateConfiguration.class).stacks();

        assertEquals(List.of("java", "python"), List.copyOf(stacks.keySet()));
        assertEquals("pom.xml", stacks.get("java").marker());
        assertEquals("pyproject.toml", stacks.get("python").marker());
    }

    @Test
    void packagedConfigCoversJavaAndPython() throws Exception {
        Map<String, StackGate> stacks = ConfigLoader.yaml().loadResource("/build-gate.yaml", BuildGateConfiguration.class).stacks();

        assertEquals(List.of("java", "python"), List.copyOf(stacks.keySet()));
        assertEquals("pom.xml", stacks.get("java").marker());
        assertEquals("pyproject.toml", stacks.get("python").marker());
        assertFalse(stacks.get("java").steps().isEmpty());
        assertFalse(stacks.get("python").steps().isEmpty());
    }

    @Test
    void missingFileThrowsLoadException(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("does-not-exist.yaml");

        ConfigLoadException ex = assertThrows(ConfigLoadException.class,
                () -> ConfigLoader.yaml().load(missing, BuildGateConfiguration.class));

        assertTrue(ex.getMessage().toLowerCase().contains("not found"));
    }

    @Test
    void malformedYamlThrowsLoadException(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("build-gate.yaml");
        Files.writeString(file, "stacks:\n  java:\n  marker: pom.xml\n    steps: [broken");

        assertThrows(ConfigLoadException.class, () -> ConfigLoader.yaml().load(file, BuildGateConfiguration.class));
    }

    @Test
    void missingRequiredCommandThrowsLoadException(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("build-gate.yaml");
        Files.writeString(file, """
                stacks:
                  java:
                    marker: pom.xml
                    steps:
                      - name: compile
                        onFailure: block
                """);

        assertThrows(ConfigLoadException.class, () -> ConfigLoader.yaml().load(file, BuildGateConfiguration.class));
    }

    @Test
    void missingMarkerThrowsLoadException(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("build-gate.yaml");
        Files.writeString(file, """
                stacks:
                  java:
                    steps:
                      - name: compile
                        command: mvn -q compile
                        onFailure: block
                """);

        assertThrows(ConfigLoadException.class, () -> ConfigLoader.yaml().load(file, BuildGateConfiguration.class));
    }

    @Test
    void unrecognizedOnFailureValueThrowsLoadException(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("build-gate.yaml");
        Files.writeString(file, """
                stacks:
                  java:
                    marker: pom.xml
                    steps:
                      - name: compile
                        command: mvn -q compile
                        onFailure: sometimes
                """);

        assertThrows(ConfigLoadException.class, () -> ConfigLoader.yaml().load(file, BuildGateConfiguration.class));
    }

    @Test
    void onFailureIsCaseInsensitive(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("build-gate.yaml");
        Files.writeString(file, """
                stacks:
                  java:
                    marker: pom.xml
                    steps:
                      - name: compile
                        command: mvn -q compile
                        onFailure: MaNuAl_ReViEw
                """);

        BuildGateStep step = ConfigLoader.yaml().load(file, BuildGateConfiguration.class).stacks().get("java").steps().getFirst();

        assertEquals(Verdict.MANUAL_REVIEW, step.onFailure());
    }

    @Test
    void loadsTheDependencyFileEachStackDeclares(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("build-gate.yaml");
        Files.writeString(file, """
                stacks:
                  python:
                    marker: pyproject.toml
                    dependencyFile: requirements.lock
                    steps:
                      - name: test
                        command: pytest -q
                        onFailure: block
                """);

        StackGate python = ConfigLoader.yaml().load(file, BuildGateConfiguration.class).stacks().get("python");

        assertEquals("pyproject.toml", python.marker());
        assertEquals("requirements.lock", python.dependencyFile(),
                "the marker says what the service is, not where its dependencies are declared");
    }

    @Test
    void aStackWithoutADependencyFileLoadsWithNone(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("build-gate.yaml");
        Files.writeString(file, """
                stacks:
                  go:
                    marker: go.mod
                    steps:
                      - name: build
                        command: go build ./...
                        onFailure: block
                """);

        StackGate go = ConfigLoader.yaml().load(file, BuildGateConfiguration.class).stacks().get("go");

        assertNull(go.dependencyFile(), "a stack the harness only builds declares no dependency file");
    }

    @Test
    void packagedConfigDeclaresADependencyFileForEveryStack() throws Exception {
        Map<String, StackGate> stacks = ConfigLoader.yaml()
                .loadResource("/build-gate.yaml", BuildGateConfiguration.class).stacks();

        assertEquals("pom.xml", stacks.get("java").dependencyFile());
        assertEquals("requirements.lock", stacks.get("python").dependencyFile());
    }

    @Test
    void aStackDeclaresWhereItsBuildPutsThings(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("build-gate.yaml");
        Files.writeString(file, """
                stacks:
                  java:
                    marker: pom.xml
                    buildOutput: [target, out]
                    steps:
                      - name: compile
                        command: mvn -q compile
                        onFailure: block
                """);

        StackGate java = ConfigLoader.yaml().load(file, BuildGateConfiguration.class).stacks().get("java");

        assertEquals(List.of("target", "out"), java.buildOutput());
    }

    @Test
    void aStackThatDeclaresNoBuildOutputHidesNothing(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("build-gate.yaml");
        Files.writeString(file, """
                stacks:
                  go:
                    marker: go.mod
                    steps:
                      - name: build
                        command: go build ./...
                        onFailure: block
                """);

        StackGate go = ConfigLoader.yaml().load(file, BuildGateConfiguration.class).stacks().get("go");

        assertEquals(List.of(), go.buildOutput(),
                "an undeclared build output must not become an unverified path");
    }

    @Test
    void packagedConfigDeclaresBuildOutputForEveryStackItBuilds() throws Exception {
        Map<String, StackGate> stacks = ConfigLoader.yaml()
                .loadResource("/build-gate.yaml", BuildGateConfiguration.class).stacks();

        assertTrue(stacks.get("java").buildOutput().contains("target"), "mvn writes target/");
        assertTrue(stacks.get("python").buildOutput().contains("__pycache__"), "python writes __pycache__/");
    }
}
