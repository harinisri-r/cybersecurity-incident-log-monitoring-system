package com.logmonitor.model;

import java.time.LocalDateTime;

/** A connection attempt to a network port. */
public class NetworkLogEntry extends LogEntry {
    private final int port;

    public NetworkLogEntry(LocalDateTime time, String host, String user, String ip, int port) {
        super(time, host, user, ip);
        this.port = port;
    }

    public int getPort() { return port; }
    @Override public String getEventType() { return "PORT_CONNECT"; }
    @Override public String getDetail() { return String.valueOf(port); }
}
