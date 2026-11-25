package com.logmonitor.rules;

import com.logmonitor.model.AuthLogEntry;
import com.logmonitor.model.Incident;
import com.logmonitor.model.IncidentCategory;
import com.logmonitor.model.LogEntry;
import com.logmonitor.model.Severity;

import java.util.Optional;

/** A successful login that follows several failures from the same IP suggests a guessed password. */
public class CompromisedLoginRule extends DetectionRule {
    private static final int MIN_FAILURES = 3;
    private static final long WINDOW_SECONDS = 120;
    private final SlidingWindow failures = new SlidingWindow();

    public CompromisedLoginRule() {
        super("Login after failures", IncidentCategory.SUSPICIOUS_LOGIN, Severity.CRITICAL);
    }

    @Override
    public synchronized Optional<Incident> evaluate(LogEntry entry) {
        if (!(entry instanceof AuthLogEntry login)) {
            return Optional.empty();
        }
        if (!login.isSuccess()) {
            failures.add(login.getIp(), login.getTime(), WINDOW_SECONDS);
            return Optional.empty();
        }
        int n = failures.count(login.getIp(), login.getTime(), WINDOW_SECONDS);
        if (n >= MIN_FAILURES) {
            failures.clear(login.getIp());
            return Optional.of(raise(login, getBaseSeverity(), "Successful login for '" + login.getUser()
                    + "' after " + n + " recent failures - possible account compromise"));
        }
        return Optional.empty();
    }

    @Override
    public String describe() { return "CRITICAL when a login succeeds after " + MIN_FAILURES + "+ failures in " + WINDOW_SECONDS + " s"; }
}
