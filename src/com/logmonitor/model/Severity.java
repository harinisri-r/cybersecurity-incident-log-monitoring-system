package com.logmonitor.model;

/** Severity levels of a security incident (LOW is the least serious). */
public enum Severity {
    LOW(1, "Low"), MEDIUM(2, "Medium"), HIGH(3, "High"), CRITICAL(4, "Critical");

    private final int level;
    private final String label;

    Severity(int level, String label) { this.level = level; this.label = label; }

    public int getLevel() { return level; }
    public String getLabel() { return label; }
    public boolean atLeast(Severity other) { return level >= other.level; }

    /** Returns the next higher severity (CRITICAL stays CRITICAL). */
    public Severity escalate() {
        Severity[] all = values();
        return this == CRITICAL ? this : all[ordinal() + 1];
    }
}
