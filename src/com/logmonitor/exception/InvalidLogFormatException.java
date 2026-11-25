package com.logmonitor.exception;

/** Thrown when a log line cannot be parsed (wrong field count, bad time, bad IP, unknown event). */
public class InvalidLogFormatException extends Exception {
    private final String line;

    public InvalidLogFormatException(String message, String line) {
        super(message);
        this.line = line;
    }

    public String getLine() { return line; }
}
