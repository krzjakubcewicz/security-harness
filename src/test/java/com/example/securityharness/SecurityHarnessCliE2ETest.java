package com.example.securityharness;

import com.example.securityharness.agent.MockLlmStub;
import com.example.securityharness.remediation.Remediator;
import com.example.securityharness.verify.ChangeVerificationFailure;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Runs the real, packaged-style CLI entry point (SecurityHarnessApp.main, in its own
 * JVM, exactly as a user would invoke it) over examples/findings-agent.json, the
 * example file this run added specifically to make the agent path reachable.
 *
 * This does not call FindingsLoader, Remediator or MockLlmStub directly - those are
 * already covered by unit and slice-level tests. It only reads the process's console
 * output, the one thing an actual user running this tool would see, and checks it
 * against the spec's acceptance criteria: both known findings load, both reach the
 * agent, and each agent call comes back as a single write call on pom.xml.
 */
class SecurityHarnessCliE2ETest {

    @Test
    void cliRunOverExampleAgentFindingsWiresStubThroughToTheAgentPath(@TempDir Path tempDir) throws Exception {
        // A service directory must exist for SecurityHarnessApp to run the workflow for it at
        // all (see groupByService / the Files.isDirectory check in main), and it must look like
        // something: the run's first step decides what the service is, and an empty directory is
        // nothing the harness knows how to build.
        Path reposRoot = tempDir.resolve("repos");
        Path service = reposRoot.resolve("inventory-api");
        Files.createDirectories(service);
        Files.writeString(service.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);

        String javaBin = System.getProperty("java.home") + File.separator + "bin" + File.separator
                + (System.getProperty("os.name", "").toLowerCase().contains("win") ? "java.exe" : "java");
        String classpath = System.getProperty("java.class.path");
        Path projectRoot = Path.of(System.getProperty("user.dir"));
        assertTrue(Files.exists(projectRoot.resolve("examples/findings-agent.json")),
                "expected to run from the project root, examples/findings-agent.json not found under " + projectRoot);

        // This temp directory is no git repository, so change verification has nothing to
        // measure against; the run below is about the agent path, not the integrity guard.
        // The guard's own end-to-end coverage is the next test.
        Process process = new ProcessBuilder(
                javaBin, "-cp", classpath, "com.example.securityharness.SecurityHarnessApp",
                "--vulnerabilities", "examples/findings-agent.json",
                "--repos", reposRoot.toString(),
                "--no-verify-changes")
                .directory(projectRoot.toFile())
                .redirectErrorStream(true)
                .start();

        String output = new String(process.getInputStream().readAllBytes());
        boolean finished = process.waitFor(90, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            fail("security-harness CLI did not finish within 90s. Output so far:\n" + output);
        }

        // S3 A1: examples/findings-agent.json yields exactly 2 findings.
        assertTrue(output.contains("Loaded 2 findings"),
                "expected the CLI to report loading 2 findings from examples/findings-agent.json. Output:\n" + output);

        // S3 A2: the strategy is picked by the finding's path. F-40218 is transitive, so it
        // reaches the agent; F-40220 is direct, so it takes the dependency-update path.
        assertTrue(output.contains("AGENT_REMEDIATION org.yaml:snakeyaml"),
                "expected F-40218's package to reach the agent path. Output:\n" + output);
        // ...but this example file publishes no fixed version for it, so the update would be a
        // no-op and is never attempted: straight to a human instead of three identical tries.
        assertTrue(output.contains("no fixed version published for commons-collections:commons-collections"),
                "expected F-40220 to be left needing attention unattempted. Output:\n" + output);
        assertFalse(output.contains("DEPENDENCY_UPDATE commons-collections:commons-collections"),
                "expected no dependency update to be attempted for F-40220. Output:\n" + output);

        // F-40218 is remediated on its first attempt, so exactly one write. F-40220
        // never calls the agent, so it contributes none.
        Matcher matches = Pattern.compile(Pattern.quote("write pom.xml")).matcher(output);
        int count = 0;
        while (matches.find()) {
            count++;
        }
        assertEquals(1, count,
                "expected exactly 1 write pom.xml tool call (F-40218, first attempt). Output:\n" + output);

        // The tool call actually landed on disk, in the service directory the CLI resolved.
        Path writtenPom = reposRoot.resolve("inventory-api").resolve("pom.xml");
        assertTrue(Files.isRegularFile(writtenPom),
                "expected the agent to write " + writtenPom + ". Output:\n" + output);
        String pom = Files.readString(writtenPom);
        assertTrue(pom.startsWith("<!-- CVE-2022-1471 fixed -->"),
                "expected F-40218's marker prepended to the pom, got:\n" + pom);
        assertTrue(pom.contains("<project/>"), "expected the seeded pom to survive the prepend, got:\n" + pom);

        // Verification reads that file, and F-40218's marker is there. F-40220 never gets that
        // far: with no fixed version published there is no update to attempt or verify.
        assertTrue(output.contains("verify F-40218: PASS"),
                "expected F-40218 to verify against the written pom. Output:\n" + output);
        assertFalse(output.contains("verify F-40220"),
                "expected F-40220 never to reach verification. Output:\n" + output);

        // F-40218 clears; F-40220 ends up with a human, unattempted.
        assertTrue(output.contains("F-40218: SUCCESS"), "Output:\n" + output);
        assertTrue(output.contains("F-40220: NEEDS_ATTENTION"), "Output:\n" + output);
    }

    /**
     * The same run against a real repository, with the integrity guard on. Both findings write
     * only pom.xml, so git's account of what changed matches what the toolbox declared and the
     * run proceeds exactly as above.
     */
    @Test
    void aRunAgainstARealRepositoryPassesChangeVerification(@TempDir Path tempDir) throws Exception {
        Path reposRoot = tempDir.resolve("repos");
        Path service = reposRoot.resolve("inventory-api");
        Files.createDirectories(service);
        seedRepo(service);

        String output = runCli(reposRoot);

        assertTrue(output.contains("change verification: clean tree"),
                "expected the guard to establish a baseline before remediating. Output:\n" + output);
        assertTrue(output.contains("change verification: 1 file(s) changed, all declared"),
                "expected both findings' writes to pom.xml to be declared and confirmed. Output:\n" + output);
        assertTrue(output.contains("verify F-40218: PASS"), "Output:\n" + output);
        assertTrue(output.contains("F-40218: SUCCESS"), "Output:\n" + output);
    }

    /**
     * A file that appeared without going through the toolbox ends the process. Standing in for
     * an escaped write here is a pre-existing uncommitted edit, which the guard refuses for the
     * same reason: it cannot tell it apart from the agent's own work.
     */
    @Test
    void aTreeTheHarnessCannotAccountForEndsTheRun(@TempDir Path tempDir) throws Exception {
        Path reposRoot = tempDir.resolve("repos");
        Path service = reposRoot.resolve("inventory-api");
        Files.createDirectories(service);
        seedRepo(service);
        Files.writeString(service.resolve("smuggled.txt"), "nobody declared this", StandardCharsets.UTF_8);

        String output = runCli(reposRoot);

        assertTrue(output.contains("smuggled.txt"),
                "expected the abort to name the file it could not account for. Output:\n" + output);
        assertTrue(output.contains("ChangeVerificationFailure"),
                "expected the failure to escape main rather than become one service that needs attention. Output:\n" + output);
        assertTrue(!output.contains("AGENT_REMEDIATION"),
                "expected the run to stop before the agent touched anything. Output:\n" + output);
    }

    /**
     * The abort above, with --output. Whoever reads the report afterwards has to be able to see
     * what stopped the run: the exit code alone does not say, and the stack trace went to a
     * console nobody kept.
     */
    @Test
    void anAbortedRunSaysWhatStoppedItInTheReport(@TempDir Path tempDir) throws Exception {
        Path reposRoot = tempDir.resolve("repos");
        Path service = reposRoot.resolve("inventory-api");
        Files.createDirectories(service);
        seedRepo(service);
        Files.writeString(service.resolve("smuggled.txt"), "nobody declared this", StandardCharsets.UTF_8);
        Path reports = tempDir.resolve("reports");

        String output = runCli(reposRoot, "--output", reports.toString());

        List<Path> written;
        try (var entries = Files.list(reports)) {
            written = entries.toList();
        }
        assertEquals(1, written.size(), "expected one report in " + reports + ". Output:\n" + output);

        String json = Files.readString(written.get(0), StandardCharsets.UTF_8);
        assertTrue(json.contains("\"type\" : \"ChangeVerificationFailure\""),
                "the report must name what aborted the run. Report:\n" + json);
        assertTrue(json.contains("smuggled.txt"),
                "the report must name the file the harness could not account for. Report:\n" + json);
        assertTrue(json.contains("\"service\" : \"inventory-api\""), json);
        assertTrue(output.contains("Run aborted:"),
                "the console should say it too, not only through the stack trace. Output:\n" + output);
    }

    /**
     * --output turns the run into a file someone else can read. The assertions here are about the
     * report existing and agreeing with the console summary, not about which strategy each finding
     * took - that is the state machine's own tests' job.
     */
    @Test
    void aRunWithAnOutputDirectoryLeavesAJsonReportBehind(@TempDir Path tempDir) throws Exception {
        Path reposRoot = tempDir.resolve("repos");
        Path service = reposRoot.resolve("inventory-api");
        Files.createDirectories(service);
        Files.writeString(service.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);
        Path reports = tempDir.resolve("reports").resolve("nested");

        String output = runCli(reposRoot, "--no-verify-changes", "--output", reports.toString());

        List<Path> written;
        try (var entries = Files.list(reports)) {
            written = entries.toList();
        }
        assertEquals(1, written.size(), "expected exactly one report in " + reports + ". Output:\n" + output);
        assertTrue(written.get(0).getFileName().toString().matches("run-\\d{8}T\\d{6}Z\\.json"),
                "unexpected report file name: " + written.get(0).getFileName());

        String json = Files.readString(written.get(0), StandardCharsets.UTF_8);
        assertTrue(json.contains("\"vulnerabilitiesFile\" : \"examples/findings-agent.json\""), json);
        assertTrue(json.contains("\"service\" : \"inventory-api\""), json);
        assertTrue(json.contains("\"id\" : \"F-40218\""), json);
        assertTrue(json.contains("\"id\" : \"F-40220\""), json);
        assertTrue(json.contains("\"total\" : 2"), json);
        // The gate ran mvn in a directory with no real project, so its verdict is in there too.
        assertTrue(json.contains("\"buildGate\""), json);
    }

    /**
     * The shipped autonomy policy, over the example findings. The seeded pom.xml is the literal
     * string "<project/>" - not a real Maven project - so the build gate's "compile" step fails
     * and the gate returns BLOCK before autonomy is decided. Against the shipped policy that
     * trips tell-the-channel-when-the-build-gate-blocked before any version-change rule gets a
     * say: a build nobody can merge is worth saying out loud on its own.
     */
    @Test
    void theRunSaysWhatItWouldDoWithTheChangesItMade(@TempDir Path tempDir) throws Exception {
        Path reposRoot = tempDir.resolve("repos");
        Path service = reposRoot.resolve("inventory-api");
        Files.createDirectories(service);
        Files.writeString(service.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);
        Path reports = tempDir.resolve("reports");

        String output = runCli(reposRoot, "--no-verify-changes", "--output", reports.toString());

        assertTrue(output.contains("autonomy: SLACK"),
                "a build the gate blocked must be flagged rather than merged or filed quietly. Output:\n" + output);
        assertTrue(output.contains("would post to the Slack channel"), "Output:\n" + output);

        List<Path> written;
        try (var entries = Files.list(reports)) {
            written = entries.toList();
        }
        String json = Files.readString(written.get(0), StandardCharsets.UTF_8);
        assertTrue(json.contains("\"autonomy\""), json);
        assertTrue(json.contains("\"action\" : \"SLACK\""), json);
    }

    @Test
    void withoutAnOutputDirectoryNothingIsWritten(@TempDir Path tempDir) throws Exception {
        Path reposRoot = tempDir.resolve("repos");
        Path service = reposRoot.resolve("inventory-api");
        Files.createDirectories(service);
        Files.writeString(service.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);

        runCli(reposRoot, "--no-verify-changes");

        try (var entries = Files.list(tempDir)) {
            assertEquals(List.of("repos"), entries.map(path -> path.getFileName().toString()).toList());
        }
    }

    /**
     * A directory that is nothing the harness recognises is not remediated at all. Before the
     * stack step existed this service ran every finding first and only then failed its gate.
     */
    @Test
    void aServiceWithNoRecognisableStackIsSentStraightToAHuman(@TempDir Path tempDir) throws Exception {
        Path reposRoot = tempDir.resolve("repos");
        Files.createDirectories(reposRoot.resolve("inventory-api"));

        String output = runCli(reposRoot, "--no-verify-changes");

        assertTrue(output.contains("No stack detected"),
                "expected the run to say it could not identify the service. Output:\n" + output);
        assertFalse(output.contains("AGENT_REMEDIATION"),
                "expected no remediation for a service the harness cannot identify. Output:\n" + output);
        assertTrue(output.contains("F-40218: NEEDS_ATTENTION"), "Output:\n" + output);
        assertTrue(output.contains("F-40220: NEEDS_ATTENTION"), "Output:\n" + output);
    }

    /** Runs the CLI in its own JVM over examples/findings-agent.json and returns its console output. */
    private static String runCli(Path reposRoot, String... extraArguments) throws Exception {
        String javaBin = System.getProperty("java.home") + File.separator + "bin" + File.separator
                + (System.getProperty("os.name", "").toLowerCase().contains("win") ? "java.exe" : "java");
        Path projectRoot = Path.of(System.getProperty("user.dir"));

        List<String> command = new ArrayList<>(List.of(
                javaBin, "-cp", System.getProperty("java.class.path"),
                "com.example.securityharness.SecurityHarnessApp",
                "--vulnerabilities", "examples/findings-agent.json",
                "--repos", reposRoot.toString()));
        command.addAll(List.of(extraArguments));

        Process process = new ProcessBuilder(command)
                .directory(projectRoot.toFile())
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes());
        if (!process.waitFor(90, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            fail("security-harness CLI did not finish within 90s. Output so far:\n" + output);
        }
        return output;
    }

    /** A repository holding one committed pom.xml - the baseline the guard measures from. */
    private static void seedRepo(Path repo) throws Exception {
        assumeGit();
        git(repo, "init", "-q");
        git(repo, "config", "user.email", "harness@example.com");
        git(repo, "config", "user.name", "Harness Test");
        git(repo, "config", "commit.gpgsign", "false");
        Files.writeString(repo.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);
        git(repo, "add", "pom.xml");
        git(repo, "commit", "-q", "-m", "seed");
    }

    /** Git is not guaranteed on a build machine; skip rather than fail there. */
    private static void assumeGit() throws Exception {
        Process process = new ProcessBuilder("git", "--version").start();
        process.getInputStream().readAllBytes();
        assumeTrue(process.waitFor() == 0, "git is not usable here");
    }

    private static void git(Path cwd, String... arguments) throws Exception {
        List<String> command = new ArrayList<>(List.of("git"));
        command.addAll(List.of(arguments));
        Process process = new ProcessBuilder(command)
                .directory(cwd.toFile())
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes());
        assumeTrue(process.waitFor() == 0,
                "test setup: git " + String.join(" ", arguments) + " failed: " + output);
    }
}
