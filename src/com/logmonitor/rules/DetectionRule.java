package com.logmonitor.rules;

import com.logmonitor.model.Incident;
import com.logmonitor.model.IncidentCategory;
import com.logmonitor.model.LogEntry;
import com.logmonitor.model.Severity;

import java.util.Optional;
import java.util.Set;

/** Abstract detection rule. Every concrete rule decides in evaluate() whether a log entry is suspicious. */
public abstract class DetectionRule {
    /** Accounts that are allowed to run administrative commands. */
    protected static final Set<String> ADMIN_USERS = Set.of("root", "admin");

    private final String name;
    private final IncidentCategory category;
    private final Severity baseSeverity;

    protected DetectionRule(String name, IncidentCategory category, Severity baseSeverity) {
        this.name = name;
        this.category = category;
        this.baseSeverity = baseSeverity;
    }

    /** Checks one log entry (method overridden by every rule). */
    public abstract Optional<Incident> evaluate(LogEntry entry);

    /** Overloaded form: only incidents of at least the given severity are returned. */
    public Optional<Incident> evaluate(LogEntry entry, Severity minimum) {
        return evaluate(entry).filter(i -> i.getSeverity().atLeast(minimum));
    }

    public abstract String describe();

    protected Incident raise(LogEntry e, Severity severity, String description) {
        return new Incident(category, severity, e.getIp(), e.getUser(), e.getHost(), description, e.getTime());
    }

    public String getName() { return name; }
    public IncidentCategory getCategory() { return category; }
    public Severity getBaseSeverity() { return baseSeverity; }
}
