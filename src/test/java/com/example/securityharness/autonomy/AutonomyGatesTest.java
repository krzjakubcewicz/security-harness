package com.example.securityharness.autonomy;

import com.example.securityharness.buildgate.BuildGateResult;
import com.example.securityharness.findings.Severity;
import com.example.securityharness.policy.Verdict;
import com.example.securityharness.remediation.FindingRecord;
import com.example.securityharness.remediation.Outcome;
import com.example.securityharness.remediation.Strategy;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AutonomyGatesTest {

    private static final BuildGateResult GREEN =
            new BuildGateResult(Verdict.ALLOW, List.of("java"), List.of());
    private static final BuildGateResult RED =
            new BuildGateResult(Verdict.BLOCK, List.of("java"), List.of());

    private static FindingRecord record(String id, String packageName, String installed,
                                        String fixed, List<String> filesChanged) {
        return new FindingRecord(id, "CVE-0000-0000", Severity.HIGH, packageName, installed, fixed,
                Strategy.DEPENDENCY_UPDATE, 1, true, List.of(), filesChanged, Outcome.SUCCESS);
    }

    /** A finding a human has to read, whose agent left fewer tests running than it found. */
    private static FindingRecord lostTests(String id, int before, int after) {
        return new FindingRecord(id, "CVE-0000-0000", Severity.HIGH, "a:b", "1.0.0", "1.0.1",
                Strategy.AGENT_REMEDIATION, false, 1, false, List.of(), List.of("src/test/java/T.java"),
                before, after, Outcome.NEEDS_ATTENTION);
    }

    private static AutonomyRule rule(String name, Map<String, Object> match, AutonomyAction action) {
        return new AutonomyRule(name, match, action);
    }

    /** The shipped policy in miniature: escalate majors, merge green dependency bumps. */
    private static AutonomyGates gates() {
        return new AutonomyGates(List.of(
                rule("escalate-major-version-changes", Map.of("versionChange", "major"),
                        AutonomyAction.JIRA),
                rule("auto-merge-green-dependency-bumps",
                        Map.of("versionChange", List.of("minor", "patch"),
                                "changeKind", "dependency_file_only",
                                "buildGate", "allow"),
                        AutonomyAction.AUTO_MERGE),
                rule("review-anything-that-touched-source", Map.of("changeKind", "source_code"),
                        AutonomyAction.PULL_REQUEST),
                rule("nothing-changed-nothing-to-ship", Map.of("changeKind", "none"),
                        AutonomyAction.NONE)));
    }

    @Test
    void anEmptyPolicyIsNotConfiguredAndDecidesNothing() {
        AutonomyGates gates = new AutonomyGates();

        assertFalse(gates.isConfigured());
        assertEquals(AutonomyAction.NONE,
                gates.decide("inventory-api", List.of(record("F-1", "a:b", "1.0.0", "1.0.1",
                        List.of("pom.xml"))), GREEN, "pom.xml").action());
    }

    @Test
    void aGreenPatchBumpOfTheDependencyFileMergesItself() {
        AutonomyDecision decision = gates().decide("inventory-api",
                List.of(record("F-1", "org.yaml:snakeyaml", "1.30.0", "1.30.1", List.of("pom.xml"))),
                GREEN, "pom.xml");

        assertEquals(AutonomyAction.AUTO_MERGE, decision.action());
        assertEquals("auto-merge-green-dependency-bumps", decision.rule());
        assertEquals("F-1", decision.finding());
    }

    @Test
    void theSameBumpWithARedBuildFallsThroughToAHuman() {
        AutonomyDecision decision = gates().decide("inventory-api",
                List.of(record("F-1", "org.yaml:snakeyaml", "1.30.0", "1.30.1", List.of("pom.xml"))),
                RED, "pom.xml");

        assertEquals(AutonomyAction.PULL_REQUEST, decision.action());
        assertNull(decision.rule(), "nothing matched - this is the default, not a rule");
    }

    @Test
    void aSourceCodeEditIsReadByAHuman() {
        AutonomyDecision decision = gates().decide("inventory-api",
                List.of(record("F-1", "org.yaml:snakeyaml", "1.30.0", "1.30.1",
                        List.of("pom.xml", "src/main/java/App.java"))),
                GREEN, "pom.xml");

        assertEquals(AutonomyAction.PULL_REQUEST, decision.action());
        assertEquals("review-anything-that-touched-source", decision.rule());
    }

    @Test
    void aMajorUpdateBeatsAPatchBumpSharingTheSameWorkingTree() {
        AutonomyDecision decision = gates().decide("inventory-api",
                List.of(record("F-1", "org.yaml:snakeyaml", "1.30.0", "1.30.1", List.of("pom.xml")),
                        record("F-2", "org.springframework.boot:spring-boot", "2.7.18", "3.2.0",
                                List.of("pom.xml"))),
                GREEN, "pom.xml");

        assertEquals(AutonomyAction.JIRA, decision.action());
        assertEquals("F-2", decision.finding(), "the decision should name the finding that forced it");
    }

    @Test
    void aFindingThatChangedNothingDoesNotSilenceItsSibling() {
        AutonomyDecision decision = gates().decide("inventory-api",
                List.of(record("F-1", "a:b", "1.0.0", "1.0.0", List.of()),
                        record("F-2", "c:d", "1.0.0", "1.0.1", List.of("pom.xml"))),
                GREEN, "pom.xml");

        assertEquals(AutonomyAction.AUTO_MERGE, decision.action());
        assertEquals("F-2", decision.finding());
    }

    @Test
    void aServiceWithNoFindingsAsksForNothing() {
        AutonomyDecision decision = gates().decide("inventory-api", List.of(), GREEN, "pom.xml");

        assertEquals(AutonomyAction.NONE, decision.action());
        assertNull(decision.finding());
    }

    @Test
    void theReasonNamesTheFactsThatDecidedIt() {
        AutonomyDecision decision = gates().decide("inventory-api",
                List.of(record("F-2", "org.springframework.boot:spring-boot", "2.7.18", "3.2.0",
                        List.of("pom.xml"))),
                GREEN, "pom.xml");

        assertTrue(decision.reason().contains("org.springframework.boot:spring-boot"), decision.reason());
        assertTrue(decision.reason().contains("2.7.18 -> 3.2.0"), decision.reason());
        assertTrue(decision.reason().contains("MAJOR"), decision.reason());
        assertTrue(decision.reason().contains("DEPENDENCY_FILE_ONLY"), decision.reason());
    }

    @Test
    void aRuleCanStillMatchOnTheFieldsGuardsMatchOn() {
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("never-touch-spring-alone", Map.of("packageName",
                        List.of("org.springframework.boot:spring-boot")), AutonomyAction.SLACK)));

        assertEquals(AutonomyAction.SLACK, gates.decide("inventory-api",
                List.of(record("F-1", "org.springframework.boot:spring-boot", "3.2.0", "3.2.1",
                        List.of("pom.xml"))), GREEN, "pom.xml").action());
    }

    @Test
    void aRuleMatchingOnAFieldThatDoesNotExistIsAConfigError() {
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("typo", Map.of("versionchnage", "major"), AutonomyAction.JIRA)));

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> gates.decide("inventory-api",
                        List.of(record("F-1", "a:b", "1.0.0", "2.0.0", List.of("pom.xml"))),
                        GREEN, "pom.xml"));
        assertTrue(thrown.getMessage().contains("typo"), thrown.getMessage());
        assertTrue(thrown.getMessage().contains("versionchnage"), thrown.getMessage());
    }

    @Test
    void aRuleAboutTheBuildGateCannotMatchAServiceThatNeverReachedIt() {
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("green-only", Map.of("buildGate", "allow"), AutonomyAction.AUTO_MERGE)));

        AutonomyDecision decision = gates.decide("inventory-api",
                List.of(record("F-1", "a:b", "1.0.0", "1.0.1", List.of("pom.xml"))), null, "pom.xml");

        assertEquals(AutonomyAction.PULL_REQUEST, decision.action());
        assertNull(decision.rule());
    }

    @Test
    void twoFindingsWantingTheSameThingKeepTheEarlierOne() {
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("major-goes-to-jira", Map.of("versionChange", "major"), AutonomyAction.JIRA),
                rule("spring-always-gets-a-ticket", Map.of("packageName",
                        List.of("org.springframework.boot:spring-boot")), AutonomyAction.JIRA)));

        AutonomyDecision decision = gates.decide("inventory-api",
                List.of(record("F-1", "org.yaml:snakeyaml", "1.30.0", "2.0.0", List.of("pom.xml")),
                        record("F-2", "org.springframework.boot:spring-boot", "3.2.0", "3.2.1",
                                List.of("pom.xml"))),
                GREEN, "pom.xml");

        assertEquals(AutonomyAction.JIRA, decision.action());
        assertEquals("F-1", decision.finding(), "a tie keeps the finding that was judged first");
    }

    @Test
    void aTypoIsAConfigErrorEvenWhenAnotherKeyInTheSameRuleWouldNotMatch() {
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("typo-beside-a-mismatch",
                        Map.of("severity", "CRITICAL", "versionchnage", "major"),
                        AutonomyAction.JIRA)));

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> gates.decide("inventory-api",
                        List.of(record("F-1", "a:b", "1.0.0", "2.0.0", List.of("pom.xml"))),
                        GREEN, "pom.xml"));

        assertTrue(thrown.getMessage().contains("versionchnage"), thrown.getMessage());
    }

    @Test
    void aGuardsStyleComparisonIsRefusedRatherThanSilentlyNeverMatching() {
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("copied-from-guards", Map.of("severity", Map.of("gte", 2)), AutonomyAction.JIRA)));

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> gates.decide("inventory-api",
                        List.of(record("F-1", "a:b", "1.0.0", "1.0.1", List.of("pom.xml"))),
                        GREEN, "pom.xml"));

        assertTrue(thrown.getMessage().contains("copied-from-guards"), thrown.getMessage());
        assertTrue(thrown.getMessage().contains("severity"), thrown.getMessage());
    }

    @Test
    void aFindingAHumanMustReadIsNotACandidateForMergingItself() {
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("a-finding-a-human-must-read", Map.of("outcome", "needs_attention"),
                        AutonomyAction.PULL_REQUEST),
                rule("auto-merge-green-dependency-bumps", Map.of("changeKind", "dependency_file_only"),
                        AutonomyAction.AUTO_MERGE)));

        AutonomyDecision decision = gates.decide("inventory-api",
                List.of(record("F-1", "a:b", "1.0.0", "1.0.1", List.of("pom.xml")),
                        lostTests("F-2", 15, 12)),
                GREEN, "pom.xml");

        assertEquals(AutonomyAction.PULL_REQUEST, decision.action());
        assertEquals("a-finding-a-human-must-read", decision.rule());
        assertEquals("F-2", decision.finding());
    }

    @Test
    void lostTestsAreWarnedAboutEvenWhenAnotherFindingWonTheDecision() {
        // The build gate blocked, so a different finding sets the action. The reviewer still has
        // to be told the suite shrank - that is the fact the pull request is for.
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("a-finding-a-human-must-read", Map.of("outcome", "needs_attention"),
                        AutonomyAction.PULL_REQUEST),
                rule("tell-the-channel-when-the-build-gate-blocked", Map.of("buildGate", "block"),
                        AutonomyAction.SLACK)));

        AutonomyDecision decision = gates.decide("inventory-api",
                List.of(lostTests("F-1", 15, 12),
                        record("F-2", "a:b", "1.0.0", "1.0.1", List.of("pom.xml"))),
                RED, "pom.xml");

        assertEquals(AutonomyAction.SLACK, decision.action());
        assertEquals("F-2", decision.finding(), "a later finding won on strictness");
        assertTrue(decision.warning().contains("F-1"), decision.warning());
        assertTrue(decision.warning().contains("12 tests"), decision.warning());
        assertTrue(decision.warning().contains("15"), decision.warning());
    }

    @Test
    void theWarningCountsInEnglishBecauseItGoesOnAPullRequest() {
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("a-finding-a-human-must-read", Map.of("outcome", "needs_attention"),
                        AutonomyAction.PULL_REQUEST)));

        AutonomyDecision decision =
                gates.decide("inventory-api", List.of(lostTests("F-1", 2, 1)), GREEN, "pom.xml");

        assertTrue(decision.warning().contains("left 1 test that will run"), decision.warning());
    }

    @Test
    void aServiceThatLostNoTestsCarriesNoWarning() {
        AutonomyDecision decision = gates().decide("inventory-api",
                List.of(record("F-1", "org.yaml:snakeyaml", "1.30.0", "1.30.1", List.of("pom.xml"))),
                GREEN, "pom.xml");

        assertNull(decision.warning(), "an ordinary remediation has nothing to flag");
    }

    /** A gate that sends every artifact in a group to a human, which is what '*' is here for. */
    private static AutonomyGates springGates() {
        return new AutonomyGates(List.of(
                rule("review-spring-updates", Map.of("packageName", "org.springframework*"),
                        AutonomyAction.PULL_REQUEST),
                rule("auto-merge-green-dependency-bumps",
                        Map.of("changeKind", "dependency_file_only", "buildGate", "allow"),
                        AutonomyAction.AUTO_MERGE)));
    }

    @Test
    void aWildcardPackageNameCoversEveryArtifactUnderIt() {
        for (String packageName : List.of("org.springframework:spring-core",
                "org.springframework.boot:spring-boot-starter", "org.springframework:spring-web")) {
            AutonomyDecision decision = springGates().decide("inventory-api",
                    List.of(record("F-1", packageName, "5.3.0", "5.3.1", List.of("pom.xml"))),
                    GREEN, "pom.xml");

            assertEquals(AutonomyAction.PULL_REQUEST, decision.action(), packageName);
            assertEquals("review-spring-updates", decision.rule(), packageName);
        }
    }

    @Test
    void aPackageOutsideTheWildcardStillMergesItself() {
        AutonomyDecision decision = springGates().decide("inventory-api",
                List.of(record("F-1", "org.yaml:snakeyaml", "1.30.0", "1.30.1", List.of("pom.xml"))),
                GREEN, "pom.xml");

        assertEquals(AutonomyAction.AUTO_MERGE, decision.action());
    }

    @Test
    void aStarCanSitAnywhereInThePackageName() {
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("any-group", Map.of("packageName", "*:spring-core"), AutonomyAction.JIRA),
                rule("anything-log4j", Map.of("packageName", "*log4j*"), AutonomyAction.SLACK)));

        assertEquals(AutonomyAction.JIRA, gates.decide("inventory-api",
                List.of(record("F-1", "org.springframework:spring-core", "5.3.0", "5.3.1",
                        List.of("pom.xml"))), GREEN, "pom.xml").action());
        assertEquals(AutonomyAction.SLACK, gates.decide("inventory-api",
                List.of(record("F-1", "org.apache.logging.log4j:log4j-core", "2.14.0", "2.14.1",
                        List.of("pom.xml"))), GREEN, "pom.xml").action());
    }

    @Test
    void oneWildcardInAListIsEnough() {
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("gated-packages", Map.of("packageName",
                        List.of("org.yaml:snakeyaml", "org.springframework*")),
                        AutonomyAction.PULL_REQUEST)));

        assertEquals("gated-packages", gates.decide("inventory-api",
                List.of(record("F-1", "org.springframework:spring-web", "5.3.0", "5.3.1",
                        List.of("pom.xml"))), GREEN, "pom.xml").rule());
    }

    @Test
    void aPackageNameWithNoStarIsStillMatchedWhole() {
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("exact-only", Map.of("packageName", "spring-core"), AutonomyAction.JIRA)));

        AutonomyDecision decision = gates.decide("inventory-api",
                List.of(record("F-1", "org.springframework:spring-core", "5.3.0", "5.3.1",
                        List.of("pom.xml"))), GREEN, "pom.xml");

        assertNull(decision.rule(), "'spring-core' is not a substring pattern");
    }

    @Test
    void theLiteralPartsOfAPatternAreNotRegex() {
        // The '.' in a Maven coordinate has to stay a dot, or every group with the right length
        // would match. This is why the pattern is quoted rather than handed to Pattern as-is.
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("spring", Map.of("packageName", "org.springframework*"), AutonomyAction.JIRA)));

        AutonomyDecision decision = gates.decide("inventory-api",
                List.of(record("F-1", "orgXspringframework:spring-core", "5.3.0", "5.3.1",
                        List.of("pom.xml"))), GREEN, "pom.xml");

        assertNull(decision.rule());
    }

    @Test
    void noOtherFieldTreatsAStarAsAWildcard() {
        AutonomyGates gates = new AutonomyGates(List.of(
                rule("every-inventory-service", Map.of("service", "inventory-*"),
                        AutonomyAction.JIRA)));

        AutonomyDecision decision = gates.decide("inventory-api",
                List.of(record("F-1", "a:b", "1.0.0", "1.0.1", List.of("pom.xml"))), GREEN, "pom.xml");

        assertNull(decision.rule(), "guards.yaml does not glob either - only packageName does");
    }
}
