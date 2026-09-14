package com.example.securityharness.agent;

import java.util.List;

public record LlmResponse(List<ToolCall> toolCalls) {
}
