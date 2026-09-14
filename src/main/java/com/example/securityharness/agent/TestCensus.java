package com.example.securityharness.agent;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * How many tests will actually run in the files the agent is about to write. Deleting a test and
 * disabling one are the same loss - the suite that would have caught a bad remediation no longer
 * catches it - so this counts declarations minus disables and reports one number for both.
 *
 * <p>It lives beside the tools because it resolves a tool call's path through the same
 * {@link WorkDirPaths} they do. A second, weaker path resolution is exactly the kind of thing that
 * turns a containment check into a suggestion.
 */
public final class TestCensus {

    /**
     * A test declaration, in either stack build-gate.yaml configures.
     *
     * <p>Java: the JUnit 5 method-level annotations, each of which declares at least one test.
     * Python: a pytest or unittest test function - 'def test...(' at the start of a line, plainly
     * or as 'async def' for pytest-asyncio, which covers both a module-level function and a method
     * of a TestCase or a Test* class, since both are written the same way.
     */
    private static final Pattern DECLARES_TEST = Pattern.compile(
            "^@(?:Test|ParameterizedTest|RepeatedTest|TestFactory|TestTemplate)\\b"
                    + "|^(?:async[ \\t]+)?def[ \\t]+test\\w*[ \\t]*\\(");

    /**
     * An annotation meaning this test will not run, or will not be believed if it does. JUnit's
     * Disabled and Ignore, unittest's skip family, and pytest's skip/skipif - plus xfail, which
     * leaves a test running but expected to fail, and so silences a regression just as completely.
     */
    private static final Pattern DISABLES_TEST = Pattern.compile(
            "^@(?:Disabled|Ignore|(?:unittest\\.)?skip\\w*|pytest\\.mark\\.(?:skip\\w*|xfail))\\b",
            Pattern.CASE_INSENSITIVE);

    /**
     * A class declaration, in either language. It matters because a disable can decorate one, and
     * that silences every test inside it - the cheapest way to empty a suite in one line.
     */
    private static final Pattern DECLARES_CLASS = Pattern.compile("^(?:\\w+[ \\t]+)*class\\b");

    private final WorkDirPaths paths;

    public TestCensus(Path workDir) {
        this.paths = new WorkDirPaths(workDir);
    }

    /**
     * File path to the tests that would run in it as it stands on disk right now, one entry per
     * distinct path. A path named twice in one response is one file and is counted once.
     *
     * @param writes the response's non-read-only calls, in the order the agent asked
     */
    public Map<String, Integer> across(List<ToolCall> writes) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (ToolCall write : writes) {
            counts.computeIfAbsent(write.filePath(),
                    path -> liveIn(readIfPresent(paths.guarded(path))));
        }
        return counts;
    }

    /**
     * Tests that would run, given this text. Walks contiguous runs of annotation or decorator
     * lines and closes each run at the first line of code, which joins it; a run counts one if it
     * declares a test and nothing in it disables that test. That is what lets an annotation
     * subtract a test without associating it by brace matching - and why the order inside a run
     * does not matter, so Disabled under Test is not a loophole.
     *
     * <p>A disable on a class declaration is the one case a run cannot express, because the tests
     * it silences are not in that run - they are every run indented under it. Those are skipped
     * until the indentation returns to the class's own, which is how both languages say "this is
     * no longer inside".
     */
    static int liveIn(String content) {
        int live = 0;
        List<String> run = new ArrayList<>();
        // The indentation of the disabled class we are inside, or -1 when we are not inside one.
        int silencedAt = -1;
        for (String line : content.split("\\R", -1)) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int indent = line.length() - line.stripLeading().length();
            // An annotation cannot close a class body: it belongs to whatever it decorates next.
            if (silencedAt >= 0 && indent <= silencedAt && !trimmed.startsWith("@")) {
                silencedAt = -1;
            }
            run.add(trimmed);
            if (trimmed.startsWith("@")) {
                continue;
            }
            if (isDisabled(run) && DECLARES_CLASS.matcher(trimmed).find()) {
                silencedAt = indent;
            } else if (silencedAt < 0 && declaresATest(run)) {
                live++;
            }
            run.clear();
        }
        // A file whose last line is an annotation: nothing closed the run, but it still declares.
        return live + (silencedAt < 0 && !isDisabled(run) && declaresATest(run) ? 1 : 0);
    }

    private static boolean declaresATest(List<String> run) {
        return run.stream().anyMatch(line -> DECLARES_TEST.matcher(line).find())
                && !isDisabled(run);
    }

    private static boolean isDisabled(List<String> run) {
        return run.stream().anyMatch(line -> DISABLES_TEST.matcher(line).find());
    }

    /** The file's text, or empty when there is no such file - a file the agent is about to create. */
    private static String readIfPresent(Path file) {
        if (!Files.isRegularFile(file)) {
            return "";
        }
        try {
            return Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + file, e);
        }
    }
}
