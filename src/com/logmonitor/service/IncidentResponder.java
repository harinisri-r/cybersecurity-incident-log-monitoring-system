package com.logmonitor.service;

import com.logmonitor.exception.IncidentNotFoundException;
import com.logmonitor.exception.InvalidStatusTransitionException;
import com.logmonitor.io.FileManager;
import com.logmonitor.model.Incident;
import com.logmonitor.model.IncidentStatus;
import com.logmonitor.model.Severity;

import java.io.IOException;

/** Monitoring thread that updates the incident records: stores, triages and raises the alert. */
public class IncidentResponder extends MonitorThread<Incident> {
    private final SecurityMonitor monitor;

    public IncidentResponder(String name, SecurityMonitor monitor) {
        super(name, monitor.incidentQueue());
        this.monitor = monitor;
    }

    @Override
    public String getRole() { return "Incident responder"; }

    @Override
    protected void process(Incident incident) {
        setStatus("TRIAGE " + incident.getCategory().getLabel());
        try {
            monitor.getManager().register(incident);
            if (incident.getSeverity().atLeast(Severity.HIGH)) {
                monitor.getManager().updateStatus(incident.getId(), IncidentStatus.INVESTIGATING);
            }
            FileManager.appendAlert(incident, monitor.getAlertFile());
            monitor.fireIncident(incident);
        } catch (IncidentNotFoundException | InvalidStatusTransitionException e) {
            System.err.println("Triage failed: " + e.getMessage());
        } catch (IOException e) {
            monitor.fireFileError("alerts.log", e.getMessage());
        } finally {
            setStatus("IDLE");
            monitor.incidentHandled();
        }
    }
}
