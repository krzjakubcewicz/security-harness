package com.example.securityharness.verify;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Holds the agent to its word: the files git reports as changed must be exactly the files the
 * Toolbox recorded writing. A difference either way means something wrote outside the one
 * chokepoint the harness trusts, so it ends the run rather than reporting a remediation.
 *
 * <p>This reads git's status, not `git diff`: a brand new pom.xml in an empty service directory
 * is untracked, and `git diff` alone cannot see untracked files.
 */
public class ChangeVerifier {
    private static final Logger log = LoggerFactory.getLogger(ChangeVerifier.class);

    private final Path serviceDirectory;
    private final Path repoRoot;

    /** The service directory as canonical() spells it, so both sides of a comparison match. */
    private final Path serviceRoot;

    /**
     * Top-level directory names the build writes into and verification therefore does not see.
     * Empty for a verifier that was told of none, which is every caller that never builds.
     */
    private final Set<String> buildOutput;

    /**
     * @throws ChangeVerificationFailure if the directory is not in a git repository, or git
     *                                   itself cannot be run - an unverifiable run is not a
     *                                   trustworthy one.
     */
    public ChangeVerifier(Path serviceDirectory) {
        this(serviceDirectory, List.of());
    }

    /**
     * @param buildOutput directories, relative to the service, whose contents are the build's own
     *                    output - see BuildGateConfiguration.StackGate. Naming one here is the
     *                    only way to make a path invisible to verification, and a 'when: tool'
     *                    guard is what stops the agent writing into the hole it opens.
     */
    public ChangeVerifier(Path serviceDirectory, Collection<String> buildOutput) {
        this.serviceDirectory = serviceDirectory.toAbsolutePath().normalize();
        this.serviceRoot = canonical(this.serviceDirectory);
        this.buildOutput = Set.copyOf(buildOutput);
        String toplevel = git("rev-parse", "--show-toplevel").trim();
        if (toplevel.isEmpty()) {
            throw new ChangeVerificationFailure("git named no repository root for " + this.serviceDirectory);
        }
        // git prints forward slashes on every platform; Path.of accepts them on Windows too.
        this.repoRoot = Path.of(toplevel).toAbsolutePath().normalize();
    }

    /**
     * Fails unless the service directory has nothing uncommitted. HEAD is the baseline the
     * comparison is measured from, so pre-existing edits would be indistinguishable from the
     * agent's.
     */
    public void requireCleanTree() {
        Set<Path> dirty = changedPaths();
        if (!dirty.isEmpty()) {
            throw new ChangeVerificationFailure(
                    "Service directory is not clean before remediation: " + relativeToRepo(dirty)
                            + ". Verification measures from HEAD - commit or stash these first,"
                            + " or re-run with --no-verify-changes.");
        }
        log.info("  change verification: clean tree at {}", repoRoot);
    }

    /**
     * Fails unless the files changed on disk are exactly {@code declared}.
     *
     * @param declared every path the Toolbox recorded writing, from Remediator.filesWritten()
     */
    public void verify(Set<Path> declared) {
        Set<Path> changed = changedPaths();
        Set<Path> expected = canonicalAll(declared);

        Set<Path> undeclared = new LinkedHashSet<>(changed);
        undeclared.removeAll(expected);
        Set<Path> unchanged = new LinkedHashSet<>(expected);
        unchanged.removeAll(changed);

        if (undeclared.isEmpty() && unchanged.isEmpty()) {
            log.info("  change verification: {} file(s) changed, all declared", changed.size());
            return;
        }

        StringBuilder message = new StringBuilder("Files changed on disk do not match what the agent declared.");
        if (!undeclared.isEmpty()) {
            message.append("\n  changed but not declared: ").append(relativeToRepo(undeclared));
        }
        if (!unchanged.isEmpty()) {
            message.append("\n  declared but unchanged: ").append(relativeToRepo(unchanged))
                    .append(" (a write that changed nothing, or a path .gitignore hides)");
        }
        throw new ChangeVerificationFailure(message.toString());
    }

    /**
     * Everything git reports as added, modified, deleted or untracked under the service
     * directory, as absolute paths.
     */
    private Set<Path> changedPaths() {
        // '-z' drops all quoting, so paths with spaces or non-ASCII need no unescaping.
        // '-uall' lists files rather than collapsing a new directory into one entry.
        // '-- .' scopes the result to this service, so a sibling service's legitimate
        // changes earlier in the same run do not show up here.
        String output = git("status", "--porcelain", "-z", "--untracked-files=all", "--", ".");
        List<String> records = List.of(output.split("\0", -1));

        Set<Path> changed = new LinkedHashSet<>();
        for (int i = 0; i < records.size(); i++) {
            String record = records.get(i);
            if (record.length() < 4) {
                continue;
            }
            char index = record.charAt(0);
            char worktree = record.charAt(1);
            add(changed, record.substring(3));
            if (isRenameOrCopy(index) || isRenameOrCopy(worktree)) {
                // A rename emits the new path, then the original as its own record. Consuming it
                // keeps the stream aligned; counting it is honest, since that path did change.
                if (++i < records.size() && !records.get(i).isEmpty()) {
                    add(changed, records.get(i));
                }
            }
        }
        return changed;
    }

    /** Adds one of git's repo-relative paths, unless it is the build's own output. */
    private void add(Set<Path> changed, String repoRelative) {
        Path path = canonical(repoRoot.resolve(repoRelative));
        if (!isBuildOutput(path)) {
            changed.add(path);
        }
    }

    /**
     * Whether the path sits inside a directory the stack declared as build output. The comparison
     * is against the whole first segment below the service, so 'targeted/' is not 'target/' and a
     * 'src/target/' that happens to hold source is still verified - the same exactness
     * ChangeKind.of relies on, and for the same reason: this is the only way a write becomes
     * invisible.
     */
    private boolean isBuildOutput(Path path) {
        if (buildOutput.isEmpty()) {
            return false;
        }
        Path relative;
        try {
            relative = serviceRoot.relativize(path);
        } catch (IllegalArgumentException e) {
            // Not below the service at all, so it is not this service's build output.
            return false;
        }
        return relative.getNameCount() > 1 && buildOutput.contains(relative.getName(0).toString());
    }

    private static boolean isRenameOrCopy(char status) {
        return status == 'R' || status == 'C';
    }

    private static Set<Path> canonicalAll(Set<Path> paths) {
        Set<Path> canonical = new LinkedHashSet<>();
        for (Path path : paths) {
            canonical.add(canonical(path));
        }
        return canonical;
    }

    /**
     * Resolves symlinks so both sides of the comparison spell the same file the same way - a
     * temp directory is a symlink on macOS, and git reports the resolved path. A path that no
     * longer exists (a deletion) keeps its absolute form.
     */
    private static Path canonical(Path path) {
        try {
            return path.toRealPath();
        } catch (IOException e) {
            return path.toAbsolutePath().normalize();
        }
    }

    /** Paths as a reader would recognise them: relative to the repo root, sorted. */
    private Set<String> relativeToRepo(Set<Path> paths) {
        Set<String> names = new TreeSet<>();
        for (Path path : paths) {
            names.add(path.startsWith(repoRoot) ? repoRoot.relativize(path).toString() : path.toString());
        }
        return names;
    }

    /** Runs git in the service directory and returns its stdout, or fails loudly. */
    private String git(String... arguments) {
        List<String> command = new ArrayList<>();
        command.add("git");
        command.addAll(List.of(arguments));
        try {
            Process process = new ProcessBuilder(command)
                    .directory(serviceDirectory.toFile())
                    .start();
            // stdout first, then stderr: git's stderr here is a line or two at most, so draining
            // them in sequence cannot fill a pipe.
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            String errors = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new ChangeVerificationFailure(
                        "git " + String.join(" ", arguments) + " failed in " + serviceDirectory
                                + " (exit " + exitCode + "): " + errors.trim());
            }
            return output;
        } catch (IOException e) {
            throw new ChangeVerificationFailure(
                    "Could not run git in " + serviceDirectory + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ChangeVerificationFailure("Interrupted running git in " + serviceDirectory, e);
        }
    }
}
