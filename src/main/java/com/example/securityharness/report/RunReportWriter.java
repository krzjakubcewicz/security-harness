package com.example.securityharness.report;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Writes one run's report into the --output directory as run-&lt;UTC timestamp&gt;.json. Runs
 * accumulate: nothing existing is overwritten.
 */
public class RunReportWriter {
    private static final Logger log = LoggerFactory.getLogger(RunReportWriter.class);

    private static final DateTimeFormatter FILE_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    private final ObjectMapper objectMapper = JsonMapper.builder().build();

    public Path write(RunReport report, Path outputDirectory) throws IOException {
        Files.createDirectories(outputDirectory);
        Path file = outputDirectory.resolve("run-" + FILE_TIMESTAMP.format(Instant.now()) + ".json");
        Files.writeString(file, toJson(report), StandardCharsets.UTF_8);
        log.info("run report written to {}", file);
        return file;
    }

    String toJson(RunReport report) {
        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(report);
    }
}
