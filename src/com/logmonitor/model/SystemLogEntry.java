package com.logmonitor.model;

import java.time.LocalDateTime;

/** A command executed by a user on a server. */
public class SystemLogEntry extends LogEntry {
    private final String command;

    public SystemLogEntry(LocalDateTime time, String host, String user, String ip, String command) {
        super(time, host, user, ip);
        this.command = command;
    }

    public String getCommand() { return command; }
    @Override public String getEventType() { return "SYSTEM_COMMAND"; }
    @Override public String getDetail() { return command; }
}
