package com.example.securityharness.autonomy;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ChangeKindTest {

    @Test
    void noFilesIsNoChange() {
        assertEquals(ChangeKind.NONE, ChangeKind.of(List.of(), "pom.xml"));
    }

    @Test
    void onlyTheDependencyFileIsADependencyChange() {
        assertEquals(ChangeKind.DEPENDENCY_FILE_ONLY, ChangeKind.of(List.of("pom.xml"), "pom.xml"));
        assertEquals(ChangeKind.DEPENDENCY_FILE_ONLY,
                ChangeKind.of(List.of("requirements.lock"), "requirements.lock"));
    }

    @Test
    void anythingElseIsSourceCode() {
        assertEquals(ChangeKind.SOURCE_CODE,
                ChangeKind.of(List.of("pom.xml", "src/main/java/App.java"), "pom.xml"));
    }

    @Test
    void aDependencyFileInASubdirectoryIsNotTheServicesOwn() {
        // The gate compares the whole relative name: a nested module's pom is not the one the
        // stack named, and treating it as one would auto-merge an edit nobody vetted.
        assertEquals(ChangeKind.SOURCE_CODE, ChangeKind.of(List.of("module/pom.xml"), "pom.xml"));
    }

    @Test
    void withNoDependencyFileNothingCanBeProvenHarmless() {
        assertEquals(ChangeKind.SOURCE_CODE, ChangeKind.of(List.of("pom.xml"), null));
    }

    @Test
    void aDifferentlyCasedNameIsNotProvablyTheDependencyFile() {
        assertEquals(ChangeKind.SOURCE_CODE, ChangeKind.of(List.of("POM.xml"), "pom.xml"));
    }
}
