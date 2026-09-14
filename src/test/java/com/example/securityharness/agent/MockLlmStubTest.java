package com.example.securityharness.agent;

import com.example.securityharness.findings.Finding;
import com.example.securityharness.findings.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MockLlmStubTest {

    @Test
    void f40218ReturnsOnePrependFileCallForSnakeyaml() {
        // A1: F-40218 returns exactly 1 ToolCall with tool="write" and filePath="pom.xml"
        LlmStub stub = new MockLlmStub();
        Finding f40218 = new Finding("F-40218", "CVE-2022-1471", Severity.CRITICAL, "inventory-api",
                "org.yaml:snakeyaml", "1.30", "transitive via org.springframework.boot:spring-boot-starter",
                null, 4, "n/a");

        LlmResponse response = stub.analyze(f40218);

        assertEquals(1, response.toolCalls().size(), "F-40218 should return exactly 1 tool call");
        assertEquals("write", response.toolCalls().get(0).tool());
        assertEquals("pom.xml", response.toolCalls().get(0).filePath());
    }

    @Test
    void f40218ContentIsTheCveMarkerComment() {
        // A2: F-40218 content is exactly the finding's "CVE-... fixed" comment, nothing else
        LlmStub stub = new MockLlmStub();
        Finding f40218 = new Finding("F-40218", "CVE-2022-1471", Severity.CRITICAL, "inventory-api",
                "org.yaml:snakeyaml", "1.30", "transitive via org.springframework.boot:spring-boot-starter",
                null, 4, "n/a");

        LlmResponse response = stub.analyze(f40218);

        assertEquals("<!-- CVE-2022-1471 fixed -->", response.toolCalls().get(0).content());
    }

    @Test
    void f40220ReturnsOnePrependFileCallForCommonsCollections() {
        // A3: F-40220 returns exactly 1 ToolCall with tool="write" and filePath="pom.xml"
        LlmStub stub = new MockLlmStub();
        Finding f40220 = new Finding("F-40220", "CVE-2015-6420", Severity.HIGH, "inventory-api",
                "commons-collections:commons-collections", "3.2.1", "direct",
                null, -63, "n/a");

        LlmResponse response = stub.analyze(f40220);

        assertEquals(1, response.toolCalls().size(), "F-40220 should return exactly 1 tool call");
        assertEquals("write", response.toolCalls().get(0).tool());
        assertEquals("pom.xml", response.toolCalls().get(0).filePath());
    }

    @Test
    void f40220ContentIsTheCveMarkerComment() {
        // A3 (cont): each finding gets its own CVE in the marker, so two markers can coexist
        LlmStub stub = new MockLlmStub();
        Finding f40220 = new Finding("F-40220", "CVE-2015-6420", Severity.HIGH, "inventory-api",
                "commons-collections:commons-collections", "3.2.1", "direct",
                null, -63, "n/a");

        LlmResponse response = stub.analyze(f40220);

        assertEquals("<!-- CVE-2015-6420 fixed -->", response.toolCalls().get(0).content());
    }

    @Test
    void unknownFindingReturnsZeroToolCalls() {
        // A4: Unknown finding returns 0 tool calls
        LlmStub stub = new MockLlmStub();
        Finding unknown = new Finding("F-40219", "CVE-2020-14343", Severity.HIGH, "report-worker",
                "PyYAML", "5.3.1", "direct",
                null, 11, "n/a");

        LlmResponse response = stub.analyze(unknown);

        assertEquals(0, response.toolCalls().size(), "Unknown finding should return zero tool calls");
        assertNotNull(response, "Response should not be null");
    }

    @Test
    void aCveWithNoStubFileReturnsZeroToolCalls() {
        // A5: the lookup is the resource file; a CVE nobody wrote a file for gets nothing
        LlmStub stub = new MockLlmStub();
        Finding noFixture = new Finding("F-40218", "CVE-9999-0000", Severity.CRITICAL, "inventory-api",
                "org.yaml:snakeyaml", "1.30", "transitive via org.springframework.boot:spring-boot-starter",
                null, 4, "n/a");

        LlmResponse response = stub.analyze(noFixture);

        assertEquals(0, response.toolCalls().size(), "A CVE with no stub file should return zero tool calls");
    }

    @Test
    void idAndPackageAreNotPartOfTheLookup() {
        // A5 (cont): lookup is by CVE alone - a different id and package still get the stubbed answer
        LlmStub stub = new MockLlmStub();
        Finding sameCveDifferentEverything = new Finding("F-99999", "CVE-2015-6420", Severity.LOW, "other-service",
                "something:else", "1.0", "direct",
                null, 0, "n/a");

        LlmResponse response = stub.analyze(sameCveDifferentEverything);

        assertEquals(1, response.toolCalls().size(), "The CVE alone selects the stubbed response");
        assertEquals("<!-- CVE-2015-6420 fixed -->", response.toolCalls().get(0).content());
    }

    @Test
    void nullFindingThrowsNullPointerException() {
        // A6: analyze(null) throws NullPointerException with exact message
        LlmStub stub = new MockLlmStub();

        NullPointerException ex = assertThrows(NullPointerException.class, () -> stub.analyze(null));
        assertEquals("finding must not be null", ex.getMessage(),
                "NullPointerException message should be exact");
    }

    @Test
    void repeatedCallsReturnIdenticalResponses() {
        // A7: Two successive analyze calls on equal F-40218 finding return equal responses
        LlmStub stub = new MockLlmStub();
        Finding f40218 = new Finding("F-40218", "CVE-2022-1471", Severity.CRITICAL, "inventory-api",
                "org.yaml:snakeyaml", "1.30", "transitive via org.springframework.boot:spring-boot-starter",
                null, 4, "n/a");

        LlmResponse response1 = stub.analyze(f40218);
        LlmResponse response2 = stub.analyze(f40218);

        assertEquals(response1.toolCalls().size(), response2.toolCalls().size(),
                "Responses should have same number of tool calls");
        assertEquals(response1.toolCalls().get(0).filePath(), response2.toolCalls().get(0).filePath(),
                "Responses should have same filePath");
        assertEquals(response1.toolCalls().get(0).content(), response2.toolCalls().get(0).content(),
                "Responses should have same content");
    }

    @Test
    void aCveThatIsNotACveIdIsNeverTurnedIntoAResourcePath() {
        // The CVE comes from an operator-supplied findings file; it must not steer the lookup
        // outside /llm-responses/. Relative segments resolve inside getResourceAsStream.
        LlmStub stub = new MockLlmStub();
        Finding traversal = new Finding("F-40218", "../guards", Severity.CRITICAL, "inventory-api",
                "org.yaml:snakeyaml", "1.30", "transitive", null, 4, "n/a");

        LlmResponse response = stub.analyze(traversal);

        assertEquals(0, response.toolCalls().size(), "A malformed CVE should return zero tool calls");
    }

    @Test
    void aNullCveReturnsZeroToolCalls() {
        LlmStub stub = new MockLlmStub();
        Finding noCve = new Finding("F-40218", null, Severity.CRITICAL, "inventory-api",
                "org.yaml:snakeyaml", "1.30", "transitive", null, 4, "n/a");

        LlmResponse response = stub.analyze(noCve);

        assertEquals(0, response.toolCalls().size(), "A finding with no CVE should return zero tool calls");
    }

    @Test
    void aStubFileThatWillNotParseFailsLoudlyRatherThanSilently() {
        // A fixture typo must not look like "this CVE has no stub" - that would pass a run
        // that never remediated anything. CVE-0000-9999.json is deliberately broken, and lives
        // in src/test/resources so it never ships in the jar.
        LlmStub stub = new MockLlmStub();
        Finding broken = new Finding("F-00000", "CVE-0000-9999", Severity.LOW, "inventory-api",
                "org.yaml:snakeyaml", "1.30", "direct", null, 0, "n/a");

        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> stub.analyze(broken));
        assertTrue(ex.getMessage().contains("CVE-0000-9999"),
                "The failure should name the unusable resource");
    }
}
