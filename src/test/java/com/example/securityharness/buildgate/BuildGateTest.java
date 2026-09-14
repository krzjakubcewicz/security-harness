package com.example.securityharness.buildgate;

import com.example.securityharness.buildgate.BuildGateConfiguration.StackGate;
import com.example.securityharness.policy.Verdict;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BuildGateTest {

    static BuildGateStep step(String name, String command, Verdict onFailure) {
        return new BuildGateStep(name, command, onFailure);
    }

    /** Both stacks write a marker file, so a test can tell which one's steps actually ran. */
    static Map<String, StackGate> javaAndPython() {
        Map<String, StackGate> stacks = new LinkedHashMap<>();
        stacks.put("java", new StackGate("pom.xml",
                List.of(step("compile", "echo ran > java-ran.txt", Verdict.BLOCK))));
        stacks.put("python", new StackGate("pyproject.toml",
                List.of(step("test", "echo ran > python-ran.txt", Verdict.BLOCK))));
        return stacks;
    }

    @Test
    void allStepsPassingReturnsAllow(@TempDir Path tempDir) {
        BuildGate gate = new BuildGate(List.of(
                step("compile", "exit 0", Verdict.BLOCK),
                step("test", "exit 0", Verdict.BLOCK)), tempDir);

        assertEquals(Verdict.ALLOW, gate.evaluate(List.of()).action());
    }

    @Test
    void blockStepFailureStopsBeforeLaterSteps(@TempDir Path tempDir) {
        Path marker = tempDir.resolve("step2-ran.txt");
        BuildGate gate = new BuildGate(List.of(
                step("compile", "exit 1", Verdict.BLOCK),
                step("test", "echo ran > step2-ran.txt", Verdict.BLOCK)), tempDir);

        assertEquals(Verdict.BLOCK, gate.evaluate(List.of()).action());
        assertFalse(Files.exists(marker), "later step must not run once a BLOCK step fails");
    }

    @Test
    void manualReviewStepFailureReturnsManualReview(@TempDir Path tempDir) {
        BuildGate gate = new BuildGate(List.of(
                step("compile", "exit 1", Verdict.MANUAL_REVIEW)), tempDir);

        assertEquals(Verdict.MANUAL_REVIEW, gate.evaluate(List.of()).action());
    }

    @Test
    void allowStepFailureContinuesToNextStep(@TempDir Path tempDir) {
        Path marker = tempDir.resolve("step2-ran.txt");
        BuildGate gate = new BuildGate(List.of(
                step("lint", "exit 1", Verdict.ALLOW),
                step("test", "echo ran > step2-ran.txt", Verdict.BLOCK)), tempDir);

        assertEquals(Verdict.ALLOW, gate.evaluate(List.of()).action());
        assertTrue(Files.exists(marker), "step after an ALLOW failure must still run");
    }

    @Test
    void unstartableCommandIsTreatedAsFailure() {
        Path missingDirectory = Path.of("this-directory-does-not-exist-" + System.nanoTime());
        BuildGate gate = new BuildGate(List.of(
                step("compile", "exit 0", Verdict.BLOCK)), missingDirectory);

        BuildGateResult result = gate.evaluate(List.of());

        assertEquals(Verdict.BLOCK, result.action());
        assertEquals(-1, result.steps().get(0).exitCode(), "an unstartable command has no exit code of its own");
    }

    @Test
    void everyStepThatRanIsNamedInTheResultWithItsExitCode(@TempDir Path tempDir) {
        BuildGate gate = new BuildGate(List.of(
                step("lint", "exit 3", Verdict.ALLOW),
                step("compile", "exit 0", Verdict.BLOCK),
                step("test", "exit 7", Verdict.BLOCK)), tempDir);

        BuildGateResult result = gate.evaluate(List.of());

        assertEquals(Verdict.BLOCK, result.action());
        assertEquals(List.of("lint", "compile", "test"),
                result.steps().stream().map(BuildGateResult.StepResult::name).toList());
        assertEquals(3, result.steps().get(0).exitCode());
        assertFalse(result.steps().get(0).passed());
        assertTrue(result.steps().get(1).passed());
        assertEquals(7, result.steps().get(2).exitCode());
    }

    @Test
    void stepsAfterABlockingFailureAreAbsentRatherThanReportedAsPassed(@TempDir Path tempDir) {
        BuildGate gate = new BuildGate(List.of(
                step("compile", "exit 1", Verdict.BLOCK),
                step("test", "exit 0", Verdict.BLOCK)), tempDir);

        assertEquals(List.of("compile"),
                gate.evaluate(List.of()).steps().stream().map(BuildGateResult.StepResult::name).toList());
    }

    @Test
    void aStepListGateDetectsNoStacks(@TempDir Path tempDir) {
        BuildGate gate = new BuildGate(List.of(step("compile", "exit 0", Verdict.BLOCK)), tempDir);

        assertEquals(List.of(), gate.evaluate(List.of()).stacks());
    }

    @Test
    void onlyTheDetectedStacksStepsRun(@TempDir Path tempDir) {
        BuildGateResult result = new BuildGate(javaAndPython(), tempDir).evaluate(List.of("java"));

        assertEquals(Verdict.ALLOW, result.action());
        assertEquals(List.of("java"), result.stacks(), "the result repeats what it was told");
        assertEquals(List.of("compile"), result.steps().stream().map(BuildGateResult.StepResult::name).toList());
        assertTrue(Files.exists(tempDir.resolve("java-ran.txt")));
        assertFalse(Files.exists(tempDir.resolve("python-ran.txt")), "python steps must not run for a Maven service");
    }

    @Test
    void aPolyglotServiceRunsBothStacksInConfigOrder(@TempDir Path tempDir) {
        BuildGateResult result = new BuildGate(javaAndPython(), tempDir)
                .evaluate(List.of("java", "python"));

        assertEquals(Verdict.ALLOW, result.action());
        assertEquals(List.of("compile", "test"),
                result.steps().stream().map(BuildGateResult.StepResult::name).toList());
        assertTrue(Files.exists(tempDir.resolve("java-ran.txt")));
        assertTrue(Files.exists(tempDir.resolve("python-ran.txt")));
    }

    @Test
    void noDetectedStackIsManualReviewAndRunsNothing(@TempDir Path tempDir) {
        BuildGateResult result = new BuildGate(javaAndPython(), tempDir).evaluate(List.of());

        assertEquals(Verdict.MANUAL_REVIEW, result.action());
        assertEquals(List.of(), result.stacks());
        assertEquals(List.of(), result.steps(), "an unidentified service must not run any step");
        assertFalse(Files.exists(tempDir.resolve("java-ran.txt")));
        assertFalse(Files.exists(tempDir.resolve("python-ran.txt")));
    }

    @Test
    void anUnconfiguredStackNameContributesNoSteps(@TempDir Path tempDir) {
        BuildGateResult result = new BuildGate(javaAndPython(), tempDir).evaluate(List.of("rust"));

        assertEquals(Verdict.ALLOW, result.action());
        assertEquals(List.of(), result.steps(), "a name with no gate configured must not blow up the run");
    }

    @Test
    void aBlockingFailureInTheFirstStackStopsBeforeTheSecond(@TempDir Path tempDir) {
        Map<String, StackGate> stacks = new LinkedHashMap<>();
        stacks.put("java", new StackGate("pom.xml", List.of(step("compile", "exit 1", Verdict.BLOCK))));
        stacks.put("python", new StackGate("pyproject.toml",
                List.of(step("test", "echo ran > python-ran.txt", Verdict.BLOCK))));

        BuildGateResult result = new BuildGate(stacks, tempDir).evaluate(List.of("java", "python"));

        assertEquals(Verdict.BLOCK, result.action());
        assertEquals(List.of("java", "python"), result.stacks());
        assertEquals(List.of("compile"), result.steps().stream().map(BuildGateResult.StepResult::name).toList());
        assertFalse(Files.exists(tempDir.resolve("python-ran.txt")));
    }
}
