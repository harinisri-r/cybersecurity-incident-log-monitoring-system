package com.logmonitor.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/** One parsed line of a system activity log (abstract parent of all log entry types). */
public abstract class LogEntry {
    public static final DateTimeFormatter FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LocalDateTime time;
    private final String host;
    private final String user;
    private final String ip;

    protected LogEntry(LocalDateTime time, String host, String user, String ip) {
        this.time = time;
        this.host = host;
        this.user = user;
        this.ip = ip;
    }

    public LocalDateTime getTime() { return time; }
    public String getHost() { return host; }
    public String getUser() { return user; }
    public String getIp() { return ip; }

    /** Name of the event as written in the log file (differs in every subclass). */
    public abstract String getEventType();

    /** The last field of the log line (differs in every subclass). */
    public abstract String getDetail();

    public boolean isAuthentication() { return false; }

    @Override
    public String toString() {
        return time.format(FORMAT) + " | " + host + " | " + getEventType() + " | " + user + " | " + ip + " | " + getDetail();
    }
}
