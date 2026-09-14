package com.example.securityharness.autonomy;

import java.util.List;

/**
 * What kind of edit a finding left behind. The distinction a gate needs is narrow and blunt: a
 * version renumbered in the file the stack declares dependencies in, versus anything else. The
 * second case is what "a human reads this" means mechanically.
 */
public enum ChangeKind {
    NONE,
    DEPENDENCY_FILE_ONLY,
    SOURCE_CODE;

    /**
     * @param filesChanged   paths relative to the service directory, forward-slashed, as
     *                       Context.addFileChanged records them
     * @param dependencyFile what the detected stack declares versions in, or null when the
     *                       harness could not say - in which case nothing is provably harmless
     */
    public static ChangeKind of(List<String> filesChanged, String dependencyFile) {
        if (filesChanged.isEmpty()) {
            return NONE;
        }
        if (dependencyFile == null) {
            return SOURCE_CODE;
        }
        for (String file : filesChanged) {
            if (!file.equals(dependencyFile)) {
                return SOURCE_CODE;
            }
        }
        return DEPENDENCY_FILE_ONLY;
    }
}
