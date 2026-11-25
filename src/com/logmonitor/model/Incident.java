package com.logmonitor.model;

import java.time.LocalDateTime;

/** A security incident record created when a detection rule fires. */
public class Incident implements Comparable<Incident> {
    private volatile String id = "-";
    private final IncidentCategory category;
    private final Severity severity;
    private final String sourceIp;
    private final String user;
    private final String host;
    private final String description;
    private final LocalDateTime time;
    private volatile IncidentStatus status = IncidentStatus.OPEN;

    public Incident(IncidentCategory category, Severity severity, String sourceIp, String user,
                    String host, String description, LocalDateTime time) {
        this.category = category;
        this.severity = severity;
        this.sourceIp = sourceIp;
        this.user = user;
        this.host = host;
        this.description = description;
        this.time = time;
    }

    public String getId() { return id; }
    public void assignId(String id) { this.id = id; }
    public IncidentCategory getCategory() { return category; }
    public Severity getSeverity() { return severity; }
    public String getSourceIp() { return sourceIp; }
    public String getUser() { return user; }
    public String getHost() { return host; }
    public String getDescription() { return description; }
    public LocalDateTime getTime() { return time; }
    public IncidentStatus getStatus() { return status; }
    public void setStatus(IncidentStatus status) { this.status = status; }

    /** Most severe first; incidents of equal severity are ordered by time. */
    @Override
    public int compareTo(Incident other) {
        int c = Integer.compare(other.severity.getLevel(), severity.getLevel());
        return c != 0 ? c : time.compareTo(other.time);
    }

    public String toCsv() {
        return String.join(",", id, time.format(LogEntry.FORMAT), severity.name(), category.name(),
                sourceIp, user, host, status.name(), "\"" + description.replace("\"", "'") + "\"");
    }

    @Override
    public String toString() {
        return "[" + severity.getLabel().toUpperCase() + "] " + id + " " + category.getLabel()
                + " | ip=" + sourceIp + " | user=" + user + " | " + description;
    }

    public String toAlertLine() { return "[" + time.format(LogEntry.FORMAT) + "] " + this; }
}
