package com.example.securityharness.remediation;

import com.example.securityharness.findings.Finding;
import com.example.securityharness.findings.Severity;
import com.example.securityharness.guards.GuardDecision;

import java.util.List;

public record FindingRecord(
        String id,
        String cve,
        Severity severity,
        String packageName,
        String installedVersion,
        String fixedVersion,
        Strategy strategy,
        boolean escalated,
        int attempts,
        boolean verified,
        List<GuardDecision> guardDecisions,
        List<String> filesChanged,
        Integer testsBefore,
        Integer testsAfter,
        Outcome outcome) {

    public FindingRecord {
        guardDecisions = List.copyOf(guardDecisions);
        filesChanged = List.copyOf(filesChanged);
    }

    /** A finding nothing counted tests for - every path but the agent's, and most of those too. */
    public FindingRecord(String id, String cve, Severity severity, String packageName,
                         String installedVersion, String fixedVersion, Strategy strategy,
                         int attempts, boolean verified, List<GuardDecision> guardDecisions,
                         List<String> filesChanged, Outcome outcome) {
        this(id, cve, severity, packageName, installedVersion, fixedVersion, strategy, false,
                attempts, verified, guardDecisions, filesChanged, null, null, outcome);
    }

    static FindingRecord of(Finding finding, Strategy strategy, boolean escalated, int attempts,
                            boolean verified, List<GuardDecision> guardDecisions,
                            List<String> filesChanged, Integer testsBefore, Integer testsAfter,
                            Outcome outcome) {
        return new FindingRecord(finding.id(), finding.cve(), finding.severity(), finding.packageName(),
                finding.installedVersion(), finding.fixedVersion(), strategy, escalated, attempts,
                verified, guardDecisions, filesChanged, testsBefore, testsAfter, outcome);
    }
}
