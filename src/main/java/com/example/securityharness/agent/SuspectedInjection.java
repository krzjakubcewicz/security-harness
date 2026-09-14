package com.example.securityharness.agent;

/**
 * Repository content that reads like an attempt to instruct the agent rather than inform it.
 * Thrown instead of returned, so the content cannot reach a caller that would hand it to a model:
 * there is no safe way to pass along text whose whole purpose is to be obeyed.
 */
public class SuspectedInjection extends RuntimeException {

    private final String filePath;
    private final String signature;

    public SuspectedInjection(String filePath, String signature) {
        super("Refusing to hand back " + filePath
                + ": content matches an injection signature (" + signature + ")");
        this.filePath = filePath;
        this.signature = signature;
    }

    /** The path as the agent asked for it. */
    public String filePath() {
        return filePath;
    }

    /** Which signature matched, for the log and the run report. */
    public String signature() {
        return signature;
    }
}
