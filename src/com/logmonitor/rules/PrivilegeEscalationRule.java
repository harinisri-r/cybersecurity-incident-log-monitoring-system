package com.logmonitor.rules;

import com.logmonitor.model.Incident;
import com.logmonitor.model.IncidentCategory;
import com.logmonitor.model.LogEntry;
import com.logmonitor.model.Severity;
import com.logmonitor.model.SystemLogEntry;

import java.util.List;
import java.util.Optional;

/** Flags privileged commands (sudo su, chmod 777 ...) run by users who are not administrators. */
public class PrivilegeEscalationRule extends DetectionRule {
    private static final List<String> RISKY = List.of("sudo su", "su -", "sudo -i", "chmod 777", "usermod -aG sudo");

    public PrivilegeEscalationRule() {
        super("Privilege escalation", IncidentCategory.PRIVILEGE_ESCALATION, Severity.HIGH);
    }

    @Override
    public Optional<Incident> evaluate(LogEntry entry) {
        if (!(entry instanceof SystemLogEntry sys) || ADMIN_USERS.contains(sys.getUser())) {
            return Optional.empty();
        }
        for (String prefix : RISKY) {
            if (sys.getCommand().startsWith(prefix)) {
                return Optional.of(raise(sys, getBaseSeverity(),
                        "Non-admin user '" + sys.getUser() + "' ran privileged command: " + sys.getCommand()));
            }
        }
        return Optional.empty();
    }

    @Override
    public String describe() { return "HIGH for privileged commands by non-admin users"; }
}
