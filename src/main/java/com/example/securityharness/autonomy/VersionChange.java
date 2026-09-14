package com.example.securityharness.autonomy;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public enum VersionChange {
    MAJOR,
    MINOR,
    PATCH,
    NONE,
    UNKNOWN;

    /** Leading numeric semver. Nine digits per segment, so a parse cannot overflow an int. */
    private static final Pattern SEMVER = Pattern.compile("^(\\d{1,9})\\.(\\d{1,9})(?:\\.(\\d{1,9}))?");

    public static VersionChange between(String installed, String fixed) {
        int[] from = parse(installed);
        int[] to = parse(fixed);
        if (from == null || to == null) {
            return UNKNOWN;
        }
        if (from[0] != to[0]) {
            return MAJOR;
        }
        if (from[1] != to[1]) {
            return MINOR;
        }
        return from[2] == to[2] ? NONE : PATCH;
    }

    /** major/minor/patch, or null when the string is not a version this can reason about. */
    private static int[] parse(String version) {
        if (version == null) {
            return null;
        }
        Matcher matcher = SEMVER.matcher(version.trim());
        if (!matcher.find()) {
            return null;
        }
        return new int[]{
                Integer.parseInt(matcher.group(1)),
                Integer.parseInt(matcher.group(2)),
                matcher.group(3) == null ? 0 : Integer.parseInt(matcher.group(3))};
    }
}
