package com.example.securityharness.verify;


public class ChangeVerificationFailure extends RuntimeException {

    public ChangeVerificationFailure(String message) {
        super(message);
    }

    public ChangeVerificationFailure(String message, Throwable cause) {
        super(message, cause);
    }
}
