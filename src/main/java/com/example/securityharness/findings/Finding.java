package com.example.securityharness.findings;

import com.fasterxml.jackson.annotation.JsonProperty;

public record Finding(
        String id,
        String cve,
        Severity severity,
        String service,
        @JsonProperty("package")
        String packageName,
        String installedVersion,
        String path,
        String fixedVersion,
        int slaDaysRemaining,
        String notes
) {
}
