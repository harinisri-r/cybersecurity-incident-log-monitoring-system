package com.logmonitor.rules;

import com.logmonitor.model.Incident;
import com.logmonitor.model.IncidentCategory;
import com.logmonitor.model.LogEntry;
import com.logmonitor.model.NetworkLogEntry;
import com.logmonitor.model.Severity;

import java.time.LocalDateTime;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/** MEDIUM when one IP touches 8 different ports within 30 s, HIGH at 16 different ports. */
public class PortScanRule extends DetectionRule {
    private static final long WINDOW_SECONDS = 30;
    private static final int MEDIUM_PORTS = 8;
    private static final int HIGH_PORTS = 16;

    private record Hit(LocalDateTime time, int port) { }
    private final Map<String, Deque<Hit>> hits = new HashMap<>();

    public PortScanRule() {
        super("Port scan detection", IncidentCategory.PORT_SCAN, Severity.MEDIUM);
    }

    @Override
    public synchronized Optional<Incident> evaluate(LogEntry entry) {
        if (!(entry instanceof NetworkLogEntry net)) {
            return Optional.empty();
        }
        Deque<Hit> window = hits.computeIfAbsent(net.getIp(), k -> new ArrayDeque<>());
        window.addLast(new Hit(net.getTime(), net.getPort()));
        while (window.peekFirst().time().plusSeconds(WINDOW_SECONDS).isBefore(net.getTime())) {
            window.removeFirst();
        }
        long distinct = window.stream().mapToInt(Hit::port).distinct().count();
        boolean newPort = window.stream().filter(h -> h.port() == net.getPort()).count() == 1;
        if (newPort && distinct == MEDIUM_PORTS) {
            return Optional.of(raise(net, getBaseSeverity(), "Possible port scan: " + distinct
                    + " different ports probed within " + WINDOW_SECONDS + " s"));
        }
        if (newPort && distinct == HIGH_PORTS) {
            return Optional.of(raise(net, getBaseSeverity().escalate(), "Aggressive port scan: " + distinct
                    + " different ports probed within " + WINDOW_SECONDS + " s"));
        }
        return Optional.empty();
    }

    @Override
    public String describe() { return "MEDIUM at " + MEDIUM_PORTS + " ports, HIGH at " + HIGH_PORTS + " ports (per IP, " + WINDOW_SECONDS + " s)"; }
}
