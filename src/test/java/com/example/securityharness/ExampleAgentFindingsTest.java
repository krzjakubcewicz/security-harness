package com.example.securityharness;

import com.example.securityharness.agent.LlmResponse;
import com.example.securityharness.config.ConfigLoader;
import com.example.securityharness.findings.Finding;
import com.example.securityharness.findings.FindingsReport;
import com.example.securityharness.findings.Severity;
import com.example.securityharness.guards.AgentGuards;
import com.example.securityharness.guards.GuardsConfiguration;
import com.example.securityharness.remediation.Context;
import com.example.securityharness.remediation.Remediator;
import com.example.securityharness.remediation.Outcome;
import com.example.securityharness.remediation.Workflow;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves examples/findings-agent.json is not just parseable but actually reaches
 * Remediator.invokeAgent through the real guards.yaml rules, and that the stub-backed
 * response is a single write call on pom.xml - the whole point of this example file.
 *
 * <p>Only F-40218 takes that path. F-40220 is a direct dependency, and the strategy is picked
 * by the finding's path, so it goes to the dependency-update side and never sees the agent.
 */
class ExampleAgentFindingsTest {

    /** Delegates to the real, stub-backed invokeAgent while recording every call. */
    static class RecordingRemediator extends Remediator {
        final List<String> agentCalls = new ArrayList<>();
        final List<LlmResponse> agentResponses = new ArrayList<>();

        @Override
        public LlmResponse invokeAgent(Finding finding, int attempt) {
            LlmResponse response = super.invokeAgent(finding, attempt);
            agentCalls.add(finding.id() + ":" + attempt);
            agentResponses.add(response);
            return response;
        }
    }

    @Test
    void exampleFileParsesIntoTwoFindingsWithNoFixedVersion() throws Exception {
        // A1: the example file yields exactly F-40218 then F-40220, neither with an upgrade path.
        List<Finding> findings = ConfigLoader.json().load(Path.of("examples/findings-agent.json"), FindingsReport.class).findings();

        assertEquals(2, findings.size());
        assertEquals("F-40218", findings.get(0).id());
        assertEquals("F-40220", findings.get(1).id());
        for (Finding finding : findings) {
            assertNull(finding.fixedVersion());
            assertEquals(Severity.HIGH, finding.severity());
            assertTrue(finding.slaDaysRemaining() >= 0);
        }
    }

    @Test
    void theTransitiveFindingRetriesToExhaustionAndEachAgentResponseIsOnePrependFile() throws Exception {
        // A2 + A3: no guard in the shipped guards.yaml stops F-40218 before the agent runs.
        // This remediator has no work directory, so nothing is written and verification can
        // never pass; with no attempt-capping rule left in guards.yaml the retries stop only
        // at maxAttempts, which is 3. Every response is one write on pom.xml.
        List<Finding> findings = ConfigLoader.json().load(Path.of("examples/findings-agent.json"), FindingsReport.class).findings();
        RecordingRemediator remediator = new RecordingRemediator();
        AgentGuards guards = new AgentGuards(ConfigLoader.yaml().loadResource("/guards.yaml", GuardsConfiguration.class).guards());
        Context context = new Context(findings);

        new Workflow(remediator, guards).run(context);

        assertEquals(List.of("F-40218:1", "F-40218:2", "F-40218:3"), remediator.agentCalls);
        assertEquals(3, remediator.agentResponses.size());
        for (LlmResponse response : remediator.agentResponses) {
            assertEquals(1, response.toolCalls().size());
            assertEquals("write", response.toolCalls().get(0).tool());
            assertEquals("pom.xml", response.toolCalls().get(0).filePath());
        }
        assertEquals(Outcome.NEEDS_ATTENTION, context.getOutcomes().get("F-40220"),
                "F-40220 is a direct dependency, so it takes the dependency-update path");
    }
}
