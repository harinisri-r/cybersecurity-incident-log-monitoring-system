package com.logmonitor.model;

/** Categories into which detected incidents are grouped. */
public enum IncidentCategory {
    BRUTE_FORCE("Brute Force Attack"),
    SUSPICIOUS_LOGIN("Suspicious Login"),
    PRIVILEGE_ESCALATION("Privilege Escalation"),
    UNAUTHORIZED_ACCESS("Unauthorized File Access"),
    PORT_SCAN("Port Scan");

    private final String label;
    IncidentCategory(String label) { this.label = label; }
    public String getLabel() { return label; }
}
