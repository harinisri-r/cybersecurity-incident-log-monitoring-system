package com.logmonitor.rules;

import com.logmonitor.model.AuthLogEntry;
import com.logmonitor.model.Incident;
import com.logmonitor.model.IncidentCategory;
import com.logmonitor.model.LogEntry;
import com.logmonitor.model.Severity;

import java.util.Optional;
import java.util.Set;

/** Flags successful logins between 22:00 and 06:00 (service accounts are exempt). */
public class OffHoursLoginRule extends DetectionRule {
    private static final Set<String> SERVICE_ACCOUNTS = Set.of("svc_backup", "svc_monitor");

    public OffHoursLoginRule() {
        super("Off-hours login", IncidentCategory.SUSPICIOUS_LOGIN, Severity.MEDIUM);
    }

    @Override
    public Optional<Incident> evaluate(LogEntry entry) {
        if (!(entry instanceof AuthLogEntry login) || !login.isSuccess()
                || SERVICE_ACCOUNTS.contains(login.getUser())) {
            return Optional.empty();
        }
        int hour = login.getTime().getHour();
        if (hour < 6 || hour >= 22) {
            return Optional.of(raise(login, getBaseSeverity(), String.format(
                    "Login for '%s' at %02d:%02d is outside working hours (06:00-22:00)",
                    login.getUser(), hour, login.getTime().getMinute())));
        }
        return Optional.empty();
    }

    @Override
    public String describe() { return "MEDIUM for successful logins between 22:00 and 06:00"; }
}
