package com.logmonitor.rules;

import com.logmonitor.model.AuthLogEntry;
import com.logmonitor.model.Incident;
import com.logmonitor.model.IncidentCategory;
import com.logmonitor.model.LogEntry;
import com.logmonitor.model.Severity;

import java.util.Optional;

/** Raises HIGH after 5 failed logins from one IP within 60 s and CRITICAL after 10. */
public class BruteForceRule extends DetectionRule {
    private static final int THRESHOLD = 5;
    private static final long WINDOW_SECONDS = 60;
    private final SlidingWindow failures = new SlidingWindow();

    public BruteForceRule() {
        super("Brute-force detection", IncidentCategory.BRUTE_FORCE, Severity.HIGH);
    }

    /** synchronized: the rule object is shared by all monitoring threads. */
    @Override
    public synchronized Optional<Incident> evaluate(LogEntry entry) {
        if (!(entry instanceof AuthLogEntry login) || login.isSuccess()) {
            return Optional.empty();
        }
        int n = failures.add(login.getIp(), login.getTime(), WINDOW_SECONDS);
        if (n == THRESHOLD) {
            return Optional.of(raise(login, getBaseSeverity(), n + " failed logins from " + login.getIp()
                    + " within " + WINDOW_SECONDS + " s (target account '" + login.getUser() + "')"));
        }
        if (n == 2 * THRESHOLD) {
            return Optional.of(raise(login, getBaseSeverity().escalate(), n + " failed logins from "
                    + login.getIp() + " within " + WINDOW_SECONDS + " s - attack continues"));
        }
        return Optional.empty();
    }

    @Override
    public String describe() { return "HIGH at " + THRESHOLD + " failures, CRITICAL at " + 2 * THRESHOLD + " (per IP, " + WINDOW_SECONDS + " s)"; }
}
