package com.example.securityharness.agent;

import com.example.securityharness.config.ConfigLoadException;
import com.example.securityharness.config.ConfigLoader;
import com.example.securityharness.findings.Finding;

import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Deterministic stand-in for a real agent. The canned answer for a CVE is the classpath resource
 * /llm-responses/&lt;CVE&gt;.json, deserialized straight into an LlmResponse; a CVE with no such file
 * gets no tool calls at all. Adding a scenario is a new resource file, not a code change.
 *
 * <p>The lookup is the CVE and nothing else - the finding's id, package and service are not
 * consulted, so two findings sharing a CVE get the same answer.
 */
public class MockLlmStub implements LlmStub {

    private static final String RESOURCE_PREFIX = "/llm-responses/";

    /**
     * Guards the resource lookup: finding.cve() is read verbatim out of an operator-supplied
     * findings file, and getResource resolves ".." segments - "../x" as a CVE would otherwise
     * reach any .json on the classpath.
     */
    private static final Pattern CVE_ID = Pattern.compile("CVE-[0-9]{4}-[0-9]{4,}");

    private static final LlmResponse NO_TOOL_CALLS = new LlmResponse(List.of());

    @Override
    public LlmResponse analyze(Finding finding) {
        Objects.requireNonNull(finding, "finding must not be null");

        String cve = finding.cve();
        if (cve == null || !CVE_ID.matcher(cve).matches()) {
            return NO_TOOL_CALLS;
        }

        String resource = RESOURCE_PREFIX + cve + ".json";
        if (getClass().getResource(resource) == null) {
            return NO_TOOL_CALLS;
        }

        LlmResponse response;
        try {
            response = ConfigLoader.json().loadResource(resource, LlmResponse.class);
        } catch (ConfigLoadException e) {
            // The file is there but will not parse: a packaging bug, not a finding we cannot answer.
            throw new IllegalStateException("Unusable stub response " + resource, e);
        }
        return response.toolCalls() == null ? NO_TOOL_CALLS : response;
    }
}
