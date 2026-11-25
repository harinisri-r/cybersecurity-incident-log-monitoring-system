package com.logmonitor.model;

import java.time.LocalDateTime;

/** A login success or login failure event. */
public class AuthLogEntry extends LogEntry {
    private final boolean success;

    public AuthLogEntry(LocalDateTime time, String host, String user, String ip, boolean success) {
        super(time, host, user, ip);
        this.success = success;
    }

    public boolean isSuccess() { return success; }
    @Override public boolean isAuthentication() { return true; }
    @Override public String getEventType() { return success ? "LOGIN_SUCCESS" : "LOGIN_FAILED"; }
    @Override public String getDetail() { return success ? "Password accepted" : "Invalid password"; }
}
