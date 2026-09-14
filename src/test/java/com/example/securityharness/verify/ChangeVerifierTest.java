package com.example.securityharness.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ChangeVerifierTest {

    @Test
    void aCommittedTreeWithNoEditsIsClean(@TempDir Path repo) throws IOException {
        seedRepo(repo);

        new ChangeVerifier(repo).requireCleanTree();
    }

    @Test
    void anUncommittedEditBeforeRemediationIsRefusedAndNamed(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        Files.writeString(repo.resolve("pom.xml"), "<project>edited</project>", StandardCharsets.UTF_8);

        ChangeVerificationFailure failure = assertThrows(ChangeVerificationFailure.class,
                () -> new ChangeVerifier(repo).requireCleanTree());
        assertTrue(failure.getMessage().contains("pom.xml"),
                "the operator has to know what to commit or stash: " + failure.getMessage());
    }

    @Test
    void changesThatWereAllDeclaredPass(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        ChangeVerifier verifier = new ChangeVerifier(repo);
        Files.writeString(repo.resolve("pom.xml"), "<!-- CVE-1 fixed -->", StandardCharsets.UTF_8);
        Files.writeString(repo.resolve("new.txt"), "added", StandardCharsets.UTF_8);

        verifier.verify(Set.of(repo.resolve("pom.xml"), repo.resolve("new.txt")));
    }

    @Test
    void aChangeNobodyDeclaredIsRefusedAndNamed(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        ChangeVerifier verifier = new ChangeVerifier(repo);
        Files.writeString(repo.resolve("pom.xml"), "<!-- CVE-1 fixed -->", StandardCharsets.UTF_8);
        Files.writeString(repo.resolve("smuggled.txt"), "written outside the toolbox", StandardCharsets.UTF_8);

        ChangeVerificationFailure failure = assertThrows(ChangeVerificationFailure.class,
                () -> verifier.verify(Set.of(repo.resolve("pom.xml"))));
        assertTrue(failure.getMessage().contains("smuggled.txt"), failure.getMessage());
        assertTrue(failure.getMessage().contains("not declared"), failure.getMessage());
    }

    @Test
    void aDeclaredWriteThatChangedNothingIsRefusedAndNamed(@TempDir Path repo) throws IOException {
        seedRepo(repo);

        ChangeVerificationFailure failure = assertThrows(ChangeVerificationFailure.class,
                () -> new ChangeVerifier(repo).verify(Set.of(repo.resolve("pom.xml"))));
        assertTrue(failure.getMessage().contains("pom.xml"), failure.getMessage());
        assertTrue(failure.getMessage().contains("declared but unchanged"), failure.getMessage());
    }

    @Test
    void aDeclaredPathThatGitignoreHidesIsRefused(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        Files.writeString(repo.resolve(".gitignore"), "secret.txt" + EOL, StandardCharsets.UTF_8);
        git(repo, "add", ".gitignore");
        git(repo, "commit", "-m", "ignore secrets");
        ChangeVerifier verifier = new ChangeVerifier(repo);
        Files.writeString(repo.resolve("secret.txt"), "agent wrote here", StandardCharsets.UTF_8);

        ChangeVerificationFailure failure = assertThrows(ChangeVerificationFailure.class,
                () -> verifier.verify(Set.of(repo.resolve("secret.txt"))));
        assertTrue(failure.getMessage().contains("secret.txt"), failure.getMessage());
    }

    @Test
    void onlyTheServiceDirectoryIsInspectedWhenItIsOneModuleOfARepo(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        Files.createDirectories(repo.resolve("inventory-api"));
        Files.createDirectories(repo.resolve("billing-api"));
        Files.writeString(repo.resolve("inventory-api/pom.xml"), "<project/>", StandardCharsets.UTF_8);
        Files.writeString(repo.resolve("billing-api/pom.xml"), "<project/>", StandardCharsets.UTF_8);
        git(repo, "add", ".");
        git(repo, "commit", "-m", "two modules");
        ChangeVerifier verifier = new ChangeVerifier(repo.resolve("inventory-api"));
        Files.writeString(repo.resolve("billing-api/pom.xml"), "<!-- someone else's work -->", StandardCharsets.UTF_8);

        verifier.requireCleanTree();
    }

    @Test
    void aChangeInTheServiceDirectoryIsFoundWhenItIsOneModuleOfARepo(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        Path service = repo.resolve("inventory-api");
        Files.createDirectories(service);
        Files.writeString(service.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);
        git(repo, "add", ".");
        git(repo, "commit", "-m", "one module");
        ChangeVerifier verifier = new ChangeVerifier(service);
        Files.writeString(service.resolve("pom.xml"), "<!-- CVE-1 fixed -->", StandardCharsets.UTF_8);

        verifier.verify(Set.of(service.resolve("pom.xml")));
    }

    @Test
    void aPathWithASpaceSurvivesTheRoundTrip(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        ChangeVerifier verifier = new ChangeVerifier(repo);
        Files.writeString(repo.resolve("my pom.xml"), "<project/>", StandardCharsets.UTF_8);

        verifier.verify(Set.of(repo.resolve("my pom.xml")));
    }

    @Test
    void aDirectoryThatIsNotInARepositoryCannotBeVerified(@TempDir Path notARepo) {
        assumeGit();

        ChangeVerificationFailure failure = assertThrows(ChangeVerificationFailure.class,
                () -> new ChangeVerifier(notARepo));
        assertTrue(failure.getMessage().contains("git"), failure.getMessage());
    }

    @Test
    void declaredBuildOutputIsNotAnUndeclaredChange(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        ChangeVerifier verifier = new ChangeVerifier(repo, List.of("target"));
        Files.writeString(repo.resolve("pom.xml"), "<!-- CVE-1 fixed -->", StandardCharsets.UTF_8);
        Files.createDirectories(repo.resolve("target/classes"));
        Files.writeString(repo.resolve("target/classes/App.class"), "compiled", StandardCharsets.UTF_8);

        verifier.verify(Set.of(repo.resolve("pom.xml")));
    }

    @Test
    void aChangeOutsideTheBuildOutputIsStillRefused(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        ChangeVerifier verifier = new ChangeVerifier(repo, List.of("target"));
        Files.writeString(repo.resolve("pom.xml"), "<!-- CVE-1 fixed -->", StandardCharsets.UTF_8);
        Files.createDirectories(repo.resolve("target"));
        Files.writeString(repo.resolve("target/App.class"), "compiled", StandardCharsets.UTF_8);
        Files.writeString(repo.resolve("smuggled.txt"), "written outside the toolbox", StandardCharsets.UTF_8);

        ChangeVerificationFailure failure = assertThrows(ChangeVerificationFailure.class,
                () -> verifier.verify(Set.of(repo.resolve("pom.xml"))));
        assertTrue(failure.getMessage().contains("smuggled.txt"), failure.getMessage());
        assertFalse(failure.getMessage().contains("App.class"),
                "ignoring build output must not make it a finding of its own: " + failure.getMessage());
    }

    @Test
    void aDirectoryWhoseNameMerelyStartsWithAnIgnoredOneIsStillVerified(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        ChangeVerifier verifier = new ChangeVerifier(repo, List.of("target"));
        Files.createDirectories(repo.resolve("targeted"));
        Files.writeString(repo.resolve("targeted/notes.txt"), "not build output", StandardCharsets.UTF_8);

        ChangeVerificationFailure failure = assertThrows(ChangeVerificationFailure.class,
                () -> verifier.verify(Set.of()));
        assertTrue(failure.getMessage().contains("notes.txt"), failure.getMessage());
    }

    @Test
    void onlyTheTopLevelBuildOutputIsHiddenNotEveryDirectoryOfThatName(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        ChangeVerifier verifier = new ChangeVerifier(repo, List.of("target"));
        Files.createDirectories(repo.resolve("src/target"));
        Files.writeString(repo.resolve("src/target/App.java"), "source that happens to live there",
                StandardCharsets.UTF_8);

        ChangeVerificationFailure failure = assertThrows(ChangeVerificationFailure.class,
                () -> verifier.verify(Set.of()));
        assertTrue(failure.getMessage().contains("App.java"), failure.getMessage());
    }

    @Test
    void buildOutputLeftByAnEarlierRunDoesNotMakeTheTreeDirty(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        Files.createDirectories(repo.resolve("target"));
        Files.writeString(repo.resolve("target/App.class"), "from the last run", StandardCharsets.UTF_8);

        new ChangeVerifier(repo, List.of("target")).requireCleanTree();
    }

    @Test
    void aVerifierToldOfNoBuildOutputStillSeesEverything(@TempDir Path repo) throws IOException {
        seedRepo(repo);
        Files.createDirectories(repo.resolve("target"));
        Files.writeString(repo.resolve("target/App.class"), "compiled", StandardCharsets.UTF_8);

        ChangeVerificationFailure failure = assertThrows(ChangeVerificationFailure.class,
                () -> new ChangeVerifier(repo).requireCleanTree());
        assertTrue(failure.getMessage().contains("App.class"), failure.getMessage());
    }

    private static final String EOL = System.lineSeparator();

    /** A repository with one committed file, which is the baseline every test measures from. */
    private static void seedRepo(Path repo) throws IOException {
        assumeGit();
        git(repo, "init", "-q");
        // A test machine need not have a global identity, and may sign commits by default.
        git(repo, "config", "user.email", "harness@example.com");
        git(repo, "config", "user.name", "Harness Test");
        git(repo, "config", "commit.gpgsign", "false");
        Files.writeString(repo.resolve("pom.xml"), "<project/>", StandardCharsets.UTF_8);
        git(repo, "add", "pom.xml");
        git(repo, "commit", "-q", "-m", "seed");
    }

    /** Git is not guaranteed on a build machine; skip rather than fail there. */
    private static void assumeGit() {
        try {
            Process process = new ProcessBuilder("git", "--version").start();
            process.getInputStream().readAllBytes();
            assumeTrue(process.waitFor() == 0, "git is not usable here");
        } catch (IOException | InterruptedException e) {
            assumeTrue(false, "git is not available here: " + e.getMessage());
        }
    }

    private static void git(Path cwd, String... arguments) {
        try {
            List<String> command = new java.util.ArrayList<>(List.of("git"));
            command.addAll(List.of(arguments));
            Process process = new ProcessBuilder(command)
                    .directory(cwd.toFile())
                    .redirectErrorStream(true)
                    .start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assumeTrue(process.waitFor() == 0,
                    "test setup: git " + String.join(" ", arguments) + " failed: " + output);
        } catch (IOException | InterruptedException e) {
            assumeTrue(false, "test setup: git " + String.join(" ", arguments) + " failed: " + e.getMessage());
        }
    }
}
