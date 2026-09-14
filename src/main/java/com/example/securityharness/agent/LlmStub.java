package com.example.securityharness.agent;

import com.example.securityharness.findings.Finding;

public interface LlmStub {
    LlmResponse analyze(Finding finding);
}
