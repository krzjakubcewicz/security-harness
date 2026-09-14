package com.example.securityharness.remediation;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The version rewriter, which is text in and text out. The point of most of these is what is
 * <em>not</em> changed: a neighbouring dependency's version, a comment, the file's formatting.
 */
class DependencyFileTest {

    /** Shaped like the real inventory-api pom: comments, a managed dependency, a pinned one. */
    private static final String POM = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project>
              <properties>
                <jackson.version>2.15.0</jackson.version>
              </properties>

              <dependencies>
                <dependency>
                  <groupId>org.springframework.boot</groupId>
                  <artifactId>spring-boot-starter-web</artifactId>
                </dependency>

                <!-- TODO(2023): migrate off commons-collections 3.x. -->
                <dependency>
                  <groupId>commons-collections</groupId>
                  <artifactId>commons-collections</artifactId>
                  <version>3.2.1</version>
                </dependency>

                <dependency>
                  <groupId>org.yaml</groupId>
                  <artifactId>snakeyaml</artifactId>
                  <version>1.30</version>
                </dependency>

                <dependency>
                  <groupId>com.fasterxml.jackson.core</groupId>
                  <artifactId>jackson-databind</artifactId>
                  <version>${jackson.version}</version>
                </dependency>
              </dependencies>
            </project>
            """;

    private static final String REQUIREMENTS = """
            # Generated. Do not edit by hand.
            PyYAML==5.3.1
            requests==2.31.0
            """;

    @Test
    void aMavenCoordinateMeansThePomWhenNoStackSaysOtherwise() {
        assertEquals("pom.xml", DependencyFile.nameFor("commons-collections:commons-collections", null));
    }

    @Test
    void abarePackageNameMeansTheRequirementsLockWhenNoStackSaysOtherwise() {
        assertEquals("requirements.lock", DependencyFile.nameFor("PyYAML", null));
    }

    @Test
    void theDetectedStacksFileWinsOverTheNameShape() {
        assertEquals("requirements.lock", DependencyFile.nameFor("PyYAML", "requirements.lock"));
        assertEquals("pom.xml", DependencyFile.nameFor("commons-collections:commons-collections", "pom.xml"));
    }

    @Test
    void theDetectedStacksFileWinsEvenWhenTheNameShapeDisagrees() {
        // A Maven-shaped coordinate in a service detected as Python only: the service is the
        // better authority on where its versions live than the shape of a scanner's string.
        assertEquals("requirements.lock",
                DependencyFile.nameFor("commons-collections:commons-collections", "requirements.lock"));
    }

    @Test
    void readsTheVersionOfTheNamedMavenDependency() {
        assertEquals("3.2.1", DependencyFile.declaredVersion(POM, "commons-collections:commons-collections"));
        assertEquals("1.30", DependencyFile.declaredVersion(POM, "org.yaml:snakeyaml"));
    }

    @Test
    void readsNoVersionForADependencyManagedByTheParent() {
        // Declared, but with no <version> of its own - there is nothing here to rewrite.
        assertNull(DependencyFile.declaredVersion(POM, "org.springframework.boot:spring-boot-starter-web"));
    }

    @Test
    void readsNoVersionForAPackageThePomDoesNotDeclare() {
        assertNull(DependencyFile.declaredVersion(POM, "org.example:absent"));
    }

    @Test
    void replacesOnlyTheNamedDependencysVersion() {
        String updated = DependencyFile.withVersion(POM, "commons-collections:commons-collections", "3.2.2");

        assertEquals("3.2.2", DependencyFile.declaredVersion(updated, "commons-collections:commons-collections"));
        assertEquals("1.30", DependencyFile.declaredVersion(updated, "org.yaml:snakeyaml"),
                "the neighbouring dependency's version must not move");
    }

    @Test
    void leavesEverythingAroundTheVersionExactlyAsItWas() {
        String updated = DependencyFile.withVersion(POM, "commons-collections:commons-collections", "3.2.2");

        assertEquals(POM.replace("<version>3.2.1</version>", "<version>3.2.2</version>"), updated);
        assertTrue(updated.startsWith("<?xml"), "the declaration stays first");
        assertTrue(updated.contains("<!-- TODO(2023): migrate off commons-collections 3.x. -->"),
                "the comment above the dependency survives");
    }

    @Test
    void replacingAnUndeclaredPackageReportsNothingToDo() {
        assertNull(DependencyFile.withVersion(POM, "org.example:absent", "1.0"));
    }

    @Test
    void readsAndReplacesAPinnedRequirement() {
        assertEquals("5.3.1", DependencyFile.declaredVersion(REQUIREMENTS, "PyYAML"));

        String updated = DependencyFile.withVersion(REQUIREMENTS, "PyYAML", "5.4");

        assertEquals(REQUIREMENTS.replace("PyYAML==5.3.1", "PyYAML==5.4"), updated);
        assertEquals("2.31.0", DependencyFile.declaredVersion(updated, "requests"));
    }

    @Test
    void matchesARequirementNameTheWayPipDoesCaseInsensitively() {
        assertEquals("5.3.1", DependencyFile.declaredVersion(REQUIREMENTS, "pyyaml"));
    }

    @Test
    void replacingAnUnpinnedRequirementReportsNothingToDo() {
        assertNull(DependencyFile.withVersion(REQUIREMENTS, "jinja2", "3.1.3"));
    }

    @Test
    void readsThePropertyReferenceAsTheDeclaredVersion() {
        // Verbatim, not resolved: what the pom says here is a reference, and reporting the
        // resolved 2.15.0 would claim a literal that is not written at this spot.
        assertEquals("${jackson.version}",
                DependencyFile.declaredVersion(POM, "com.fasterxml.jackson.core:jackson-databind"));
    }

    @Test
    void refusesToRewriteAVersionHeldInAProperty() {
        // Splicing over the reference would pin the version here and leave the property stale,
        // so the version would then be declared in two places.
        assertNull(DependencyFile.withVersion(POM, "com.fasterxml.jackson.core:jackson-databind", "2.17.1"));
        assertTrue(POM.contains("<version>${jackson.version}</version>"), "the reference is left alone");
    }

    @Test
    void stillRewritesTheDependenciesThatDoPinALiteralVersion() {
        // The property guard has to be narrow: its neighbours in the same pom still move.
        assertEquals("1.31", DependencyFile.declaredVersion(
                DependencyFile.withVersion(POM, "org.yaml:snakeyaml", "1.31"), "org.yaml:snakeyaml"));
    }
}
