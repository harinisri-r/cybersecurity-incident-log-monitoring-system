package com.logmonitor.service;

import com.logmonitor.exception.IncidentNotFoundException;
import com.logmonitor.exception.InvalidStatusTransitionException;
import com.logmonitor.model.Incident;
import com.logmonitor.model.IncidentCategory;
import com.logmonitor.model.IncidentStatus;
import com.logmonitor.model.Severity;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** Thread-safe store of all incident records, with statistics. */
public class IncidentManager {
    private final AtomicInteger sequence = new AtomicInteger(1000);
    private final List<Incident> incidents = new ArrayList<>();
    private final Map<IncidentCategory, Integer> byCategory = new EnumMap<>(IncidentCategory.class);
    private final Map<Severity, Integer> bySeverity = new EnumMap<>(Severity.class);
    private final Map<String, Integer> byIp = new HashMap<>();

    /** Stores a new incident and gives it the next incident number. */
    public synchronized void register(Incident incident) {
        incident.assignId("INC-" + sequence.incrementAndGet());
        incidents.add(incident);
        byCategory.merge(incident.getCategory(), 1, Integer::sum);
        bySeverity.merge(incident.getSeverity(), 1, Integer::sum);
        byIp.merge(incident.getSourceIp(), 1, Integer::sum);
    }

    /** Updates the status of an incident record (only forward transitions are allowed). */
    public synchronized void updateStatus(String id, IncidentStatus next)
            throws IncidentNotFoundException, InvalidStatusTransitionException {
        Incident incident = find(id);
        if (!incident.getStatus().canMoveTo(next)) {
            throw new InvalidStatusTransitionException(id, incident.getStatus(), next);
        }
        incident.setStatus(next);
    }

    public synchronized Incident find(String id) throws IncidentNotFoundException {
        for (Incident i : incidents) {
            if (i.getId().equals(id)) return i;
        }
        throw new IncidentNotFoundException(id);
    }

    /** All incidents, most severe first (a copy is returned). */
    public synchronized List<Incident> getIncidents() {
        List<Incident> copy = new ArrayList<>(incidents);
        Collections.sort(copy);
        return copy;
    }

    /** Overloaded: only incidents of one severity. */
    public synchronized List<Incident> getIncidents(Severity severity) {
        return getIncidents().stream().filter(i -> i.getSeverity() == severity).toList();
    }

    /** Overloaded: only incidents of one category. */
    public synchronized List<Incident> getIncidents(IncidentCategory category) {
        return getIncidents().stream().filter(i -> i.getCategory() == category).toList();
    }

    public synchronized int getTotal() { return incidents.size(); }
    public synchronized int getCount(Severity s) { return bySeverity.getOrDefault(s, 0); }
    public synchronized int getCount(IncidentCategory c) { return byCategory.getOrDefault(c, 0); }
    public synchronized int getCount(IncidentStatus s) {
        return (int) incidents.stream().filter(i -> i.getStatus() == s).count();
    }

    /** Source IPs ordered by number of incidents. */
    public synchronized List<Map.Entry<String, Integer>> topSources(int limit) {
        List<Map.Entry<String, Integer>> list = new ArrayList<>(byIp.entrySet());
        list.sort((a, b) -> b.getValue() != a.getValue().intValue()
                ? b.getValue() - a.getValue() : a.getKey().compareTo(b.getKey()));
        return list.subList(0, Math.min(limit, list.size()));
    }

    public synchronized String buildReport() {
        StringBuilder sb = new StringBuilder();
        String line = "-".repeat(60);
        sb.append("SECURITY INCIDENT SUMMARY REPORT - ")
          .append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))).append('\n')
          .append(line).append('\n')
          .append(String.format("%-30s %s%n", "Category", "Incidents")).append(line).append('\n');
        for (IncidentCategory c : IncidentCategory.values()) {
            sb.append(String.format("%-30s %5d%n", c.getLabel(), getCount(c)));
        }
        sb.append(line).append('\n').append(String.format("%-30s %5d%n", "TOTAL", incidents.size()));
        sb.append("\nBy severity : ");
        for (Severity s : Severity.values()) {
            sb.append(s.getLabel()).append(' ').append(getCount(s)).append("   ");
        }
        sb.append("\nBy status   : ");
        for (IncidentStatus s : IncidentStatus.values()) {
            sb.append(s).append(' ').append(getCount(s)).append("   ");
        }
        sb.append("\n\nTop source IP addresses:\n");
        for (Map.Entry<String, Integer> e : topSources(5)) {
            sb.append(String.format("  %-16s %d incident(s)%n", e.getKey(), e.getValue()));
        }
        return sb.toString();
    }
}
