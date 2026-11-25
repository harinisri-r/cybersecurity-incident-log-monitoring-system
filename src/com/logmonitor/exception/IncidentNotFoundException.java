package com.logmonitor.exception;

/** Thrown when an incident id does not exist in the incident records. */
public class IncidentNotFoundException extends Exception {
    public IncidentNotFoundException(String id) { super("Incident not found: " + id); }
}
