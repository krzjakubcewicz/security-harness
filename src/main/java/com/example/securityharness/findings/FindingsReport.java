package com.example.securityharness.findings;

import java.time.Instant;
import java.util.List;

public record FindingsReport(Instant generated, String scanner, List<Finding> findings) {
}
