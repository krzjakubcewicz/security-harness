package com.example.securityharness.agent;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * Confines tool file paths to the work directory. Shared by every tool that touches a file, and
 * deliberately not configurable: a containment check has to fail closed. Which paths inside the
 * work directory are off limits is policy, and lives in guards.yaml as 'when: tool' rules.
 */
final class WorkDirPaths {

    private final Path workDir;

    WorkDirPaths(Path workDir) {
        this.workDir = workDir.toAbsolutePath().normalize();
    }

    /**
     * The absolute path the call may touch, or an IllegalArgumentException. Refuses anything
     * outside the work directory - textually or through a symlink - and anything that is not a
     * regular file.
     */
    Path guarded(String filePath) {
        if (filePath == null || filePath.isBlank()) {
            throw new IllegalArgumentException("Tool call is missing a file path");
        }
        Path target = workDir.resolve(filePath).normalize();
        if (!target.startsWith(workDir) || target.equals(workDir)) {
            throw new IllegalArgumentException("Tool call escapes the work directory: " + filePath);
        }
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS) && !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Tool call target is not a regular file: " + filePath);
        }
        if (!realAncestor(target).startsWith(real(workDir))) {
            throw new IllegalArgumentException("Tool call escapes the work directory: " + filePath);
        }
        return target;
    }

    /** The nearest ancestor of target that exists on disk, with symlinks resolved. */
    private Path realAncestor(Path target) {
        Path existing = target;
        while (!Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
            existing = existing.getParent();
        }
        return real(existing);
    }

    private Path real(Path path) {
        try {
            return path.toRealPath();
        } catch (IOException e) {
            throw new UncheckedIOException("Could not resolve " + path, e);
        }
    }
}
