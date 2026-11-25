package com.logmonitor.model;

/** Life cycle of an incident record: OPEN -> INVESTIGATING -> RESOLVED. */
public enum IncidentStatus {
    OPEN, INVESTIGATING, RESOLVED;

    /** An incident can only move forward in its life cycle. */
    public boolean canMoveTo(IncidentStatus next) {
        return switch (this) {
            case OPEN -> next != OPEN;
            case INVESTIGATING -> next == RESOLVED;
            case RESOLVED -> false;
        };
    }
}
