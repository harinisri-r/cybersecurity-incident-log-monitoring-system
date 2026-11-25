package com.logmonitor.rules;

import com.logmonitor.model.Incident;
import com.logmonitor.model.IncidentCategory;
import com.logmonitor.model.LogEntry;
import com.logmonitor.model.Severity;
import com.logmonitor.model.SystemLogEntry;

import java.util.Optional;

/** Flags access to password files by users who are not administrators. */
public class SensitiveFileRule extends DetectionRule {
    public SensitiveFileRule() {
        super("Sensitive file access", IncidentCategory.UNAUTHORIZED_ACCESS, Severity.HIGH);
    }

    @Override
    public Optional<Incident> evaluate(LogEntry entry) {
        if (entry instanceof SystemLogEntry sys && !ADMIN_USERS.contains(sys.getUser())
                && (sys.getCommand().contains("/etc/shadow") || sys.getCommand().contains("/etc/passwd"))) {
            return Optional.of(raise(sys, getBaseSeverity(),
                    "User '" + sys.getUser() + "' accessed a password file: " + sys.getCommand()));
        }
        return Optional.empty();
    }

    @Override
    public String describe() { return "HIGH for /etc/shadow or /etc/passwd access by non-admin users"; }
}
