package com.example.securityharness.remediation;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads and rewrites the version a dependency file declares for one package. Pure text in, text
 * out - no I/O, so the Remediator owns where the bytes come from and who records the write.
 *
 * <p>Two formats, told apart by the package name: "group:artifact" is a Maven coordinate and means
 * pom.xml, anything else is a pip requirement line. Both edits are targeted - only the version
 * characters are replaced, so comments and formatting around them come through untouched.
 */
final class DependencyFile {

    /** One <dependency> element, however its children are ordered. */
    private static final Pattern DEPENDENCY_BLOCK = Pattern.compile("(?s)<dependency>(.*?)</dependency>");

    /** The version text inside a block, group 1. Stops at the first '<', so it is the value alone. */
    private static final Pattern VERSION_ELEMENT = Pattern.compile("<version>\\s*([^<\\s]+)");

    /**
     * The file a package's version is declared in, relative to the service directory. The
     * detected stack's own answer wins - it is a fact about this service, where the package name
     * is only a guess from its shape. Without one, because nothing was detected or because a
     * polyglot service has two such files, the shape decides as it did before detection existed.
     */
    static String nameFor(String packageName, String stackDependencyFile) {
        return Objects.requireNonNullElse(stackDependencyFile, isMavenCoordinate(packageName) ? "pom.xml" : "requirements.lock");
    }

    /** The version {@code content} currently declares for the package, or null if it declares none. */
    static String declaredVersion(String content, String packageName) {
        int[] span = versionSpan(content, packageName);
        return span == null ? null : content.substring(span[0], span[1]);
    }

    /**
     * {@code content} with that package's declared version replaced, or null when the package is
     * not declared here - the caller reports that rather than guessing where else to look.
     * Null too when the version it declares is a property reference - see isPropertyReference.
     */
    static String withVersion(String content, String packageName, String version) {
        int[] span = versionSpan(content, packageName);
        if (span == null) {
            return null;
        }
        if (isPropertyReference(content.substring(span[0], span[1]))) {
            return null;
        }
        return content.substring(0, span[0]) + version + content.substring(span[1]);
    }

    /**
     * A version Maven resolves elsewhere, e.g. ${jackson.version} - a reference, not a literal to
     * overwrite. Splicing a version over it would pin the version here and leave the property it
     * came from still declared, so the same dependency would be versioned in two places.
     */
    static boolean isPropertyReference(String version) {
        return version != null && version.startsWith("${");
    }

    /** Where the declared version starts and ends in {@code content}, or null if it is not declared. */
    private static int[] versionSpan(String content, String packageName) {
        if (content == null || packageName == null || packageName.isBlank()) {
            return null;
        }
        return isMavenCoordinate(packageName)
                ? mavenVersionSpan(content, packageName)
                : pipVersionSpan(content, packageName);
    }

    /** The <version> of the one <dependency> block declaring this coordinate. */
    private static int[] mavenVersionSpan(String content, String coordinate) {
        String[] parts = coordinate.split(":", 2);
        Matcher blocks = DEPENDENCY_BLOCK.matcher(content);
        while (blocks.find()) {
            String block = blocks.group(1);
            if (!declares(block, "groupId", parts[0]) || !declares(block, "artifactId", parts[1])) {
                continue;
            }
            Matcher version = VERSION_ELEMENT.matcher(block);
            if (version.find()) {
                int blockStart = blocks.start(1);
                return new int[]{blockStart + version.start(1), blockStart + version.end(1)};
            }
            // Declared with no version of its own: managed by a parent pom, nothing to rewrite here.
            return null;
        }
        return null;
    }

    /** The version on this package's "name==version" line, case-insensitive the way pip is. */
    private static int[] pipVersionSpan(String content, String packageName) {
        Matcher requirement = Pattern
                .compile("(?im)^" + Pattern.quote(packageName) + "\\s*==\\s*([^\\s#]+)")
                .matcher(content);
        return requirement.find() ? new int[]{requirement.start(1), requirement.end(1)} : null;
    }

    private static boolean declares(String block, String element, String value) {
        return Pattern.compile("<" + element + ">\\s*" + Pattern.quote(value) + "\\s*</" + element + ">")
                .matcher(block).find();
    }

    private static boolean isMavenCoordinate(String packageName) {
        return packageName != null && packageName.contains(":");
    }
}
