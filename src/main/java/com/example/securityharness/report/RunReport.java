package com.example.securityharness.report;

import com.example.securityharness.autonomy.AutonomyDecision;
import com.example.securityharness.buildgate.BuildGateResult;
import com.example.securityharness.remediation.Context;
import com.example.securityharness.remediation.FindingRecord;
import com.example.securityharness.remediation.Outcome;

import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The machine-readable account of one run: what was asked, what the harness did to each finding,
 * and how it ended. Serialised to JSON by {@link RunReportWriter} when --output is given.
 *
 * Timestamps are ISO-8601 strings rather than Instants so the JSON shape does not depend on
 * Jackson's date configuration.
 */
public record RunReport(Run run, Summary summary, List<Service> services) {

    /** abort is null when the run finished on its own terms, however badly it went. */
    public record Run(String startedAt, String finishedAt, String vulnerabilitiesFile,
                      String reposRoot, int exitCode, Abort abort) {
    }

    /**
     * What ended the run before it could finish. The exit code alone says a run failed; this says
     * what stopped it and which service it was on, because the message names the files the harness
     * could not account for and nothing else in the report does.
     */
    public record Abort(String type, String service, String message) {
    }

    /** notProcessed counts findings the run never reached - a missing service directory, an abort. */
    public record Summary(int total, int success, int needsAttention, int notProcessed) {
    }

    /** buildGate is null when the service never reached the gate; autonomy when no gate ran. */
    public record Service(String service, String directory, Outcome endState,
                          BuildGateResult buildGate, AutonomyDecision autonomy,
                          List<FindingRecord> findings) {
    }

    public static RunReport of(Instant startedAt, Instant finishedAt, String vulnerabilitiesFile,
                               Path reposRoot, int exitCode,
                               Map<String, Context> contexts,
                               Map<String, Path> serviceDirectories,
                               Abort abort) {
        List<Service> services = new ArrayList<>();
        int total = 0;
        int success = 0;
        int needsAttention = 0;

        for (Map.Entry<String, Context> entry : contexts.entrySet()) {
            Context context = entry.getValue();
            Path directory = serviceDirectories.get(entry.getKey());
            services.add(new Service(
                    entry.getKey(),
                    directory == null ? null : directory.toString(),
                    context.getOutcome(),
                    context.getBuildGate(),
                    context.getAutonomy(),
                    context.getRecords()));

            total += context.findingCount();
            for (FindingRecord record : context.getRecords()) {
                // No default on purpose: a new Outcome constant should not compile until it is
                // counted here.
                switch (record.outcome()) {
                    case SUCCESS -> success++;
                    case NEEDS_ATTENTION -> needsAttention++;
                }
            }
        }

        return new RunReport(
                new Run(DateTimeFormatter.ISO_INSTANT.format(startedAt),
                        DateTimeFormatter.ISO_INSTANT.format(finishedAt),
                        vulnerabilitiesFile,
                        reposRoot == null ? null : reposRoot.toString(),
                        exitCode,
                        abort),
                new Summary(total, success, needsAttention, total - success - needsAttention),
                List.copyOf(services));
    }
}
