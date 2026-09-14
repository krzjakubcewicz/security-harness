package com.example.securityharness.agent;

import java.util.List;
import java.util.regex.Pattern;

final class UntrustedContent {

    /** The most characters handed back from one file. Beyond this the tail is dropped, not refused. */
    static final int MAX_CHARACTERS = 65_536;

    private static final String OPEN = "<untrusted-file-content";
    private static final String CLOSE = "</untrusted-file-content>";

    private record Redaction(Pattern pattern, String replacement) {
    }

    /** Secret shapes worth masking before anything sees them. Applied in order. */
    private static final List<Redaction> REDACTIONS = List.of(
            new Redaction(Pattern.compile(
                    "(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
                    "[REDACTED PRIVATE KEY]"),
            new Redaction(Pattern.compile("AKIA[0-9A-Z]{16}"), "[REDACTED]"),
            new Redaction(Pattern.compile("gh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED]"),
            new Redaction(Pattern.compile("(?i)\\bbearer\\s+[A-Za-z0-9._\\-]{16,}"), "Bearer [REDACTED]"),
            // The key stays: "the file sets a password here" is useful, the password is not.
            new Redaction(Pattern.compile(
                    "(?im)^([ \\t]*[\"']?(?:password|passwd|secret|token|api[_-]?key|access[_-]?key"
                            + "|authorization)[\"']?[ \\t]*[:=][ \\t]*)\\S+"),
                    "$1[REDACTED]"));

    private record Signature(String name, Pattern pattern) {
    }

    /** Content shapes that are trying to be instructions. First match wins and names the refusal. */
    private static final List<Signature> SIGNATURES = List.of(
            new Signature("override-instructions", Pattern.compile(
                    "(?i)\\b(ignore|disregard|forget)\\b[^.\\n]{0,40}"
                            + "\\b(previous|prior|earlier|above|all)\\b[^.\\n]{0,40}"
                            + "\\b(instruction|prompt|rule)s?\\b")),
            new Signature("new-instructions", Pattern.compile(
                    "(?i)\\b(new|updated|additional|revised)\\s+(instruction|directive|system prompt)s?\\b\\s*:")),
            new Signature("forged-role-marker", Pattern.compile(
                    "(?im)<\\s*/?\\s*(system|assistant|user)\\s*>|^\\s*(###\\s*)?(system|assistant)\\s*:")),
            new Signature("forged-tool-call", Pattern.compile(
                    "(?i)\"tool\"\\s*:\\s*\"(write|writeFile|readFile)\"")),
            // Escaping this one instead would be unreachable: every spelling that could be escaped
            // is refused here first.
            new Signature("forged-content-delimiter", Pattern.compile(
                    "(?i)<\\s*/?\\s*untrusted-file-content")));

    private UntrustedContent() {
    }

    /**
     * {@code text} framed as untrusted data: truncated to the cap, secrets masked, wrapped in
     * delimiters that name the file.
     *
     * @param filePath   the path as the agent asked for it, for the wrapper's attribute
     * @param text       more than MAX_CHARACTERS of it means the read is reported as truncated
     * @param totalBytes the file's real size on disk, so a truncated read says what it left out
     * @throws SuspectedInjection when the content matches a signature
     */
    static String wrapped(String filePath, String text, long totalBytes) {
        boolean truncated = text.length() > MAX_CHARACTERS;
        String body = redacted(truncated ? text.substring(0, MAX_CHARACTERS) : text);

        for (Signature signature : SIGNATURES) {
            if (signature.pattern().matcher(body).find()) {
                throw new SuspectedInjection(filePath, signature.name());
            }
        }

        StringBuilder wrapped = new StringBuilder(body.length() + 128);
        wrapped.append(OPEN).append(" path=\"").append(attribute(filePath)).append('"');
        if (truncated) {
            wrapped.append(" truncated=\"true\"");
        }
        wrapped.append(">\n").append(body);
        if (!body.endsWith("\n")) {
            wrapped.append('\n');
        }
        if (truncated) {
            wrapped.append("[truncated: first ").append(MAX_CHARACTERS)
                    .append(" characters of ").append(totalBytes).append(" bytes shown]\n");
        }
        return wrapped.append(CLOSE).toString();
    }

    private static String redacted(String text) {
        String masked = text;
        for (Redaction redaction : REDACTIONS) {
            masked = redaction.pattern().matcher(masked).replaceAll(redaction.replacement());
        }
        return masked;
    }

    /** A path the agent chose cannot be trusted to stay inside the attribute it is printed in. */
    private static String attribute(String filePath) {
        return filePath
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
