package com.logmonitor.exception;

import com.logmonitor.model.IncidentStatus;

/** Thrown when an incident is moved backwards in its life cycle (e.g. RESOLVED to OPEN). */
public class InvalidStatusTransitionException extends Exception {
    public InvalidStatusTransitionException(String id, IncidentStatus from, IncidentStatus to) {
        super("Cannot change " + id + " from " + from + " to " + to);
    }
}
