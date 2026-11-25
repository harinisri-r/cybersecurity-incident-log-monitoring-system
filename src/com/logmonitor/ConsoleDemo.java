package com.logmonitor;

import com.logmonitor.exception.IncidentNotFoundException;
import com.logmonitor.exception.InvalidStatusTransitionException;
import com.logmonitor.io.SampleLogGenerator;
import com.logmonitor.model.Incident;
import com.logmonitor.model.IncidentStatus;
import com.logmonitor.model.Severity;
import com.logmonitor.service.MonitorListener;
import com.logmonitor.service.MonitorThread;
import com.logmonitor.service.SecurityMonitor;

import java.nio.file.Path;
import java.util.List;

/** Text-mode demonstration: four log files are monitored together by the worker threads. */
public final class ConsoleDemo {
    private ConsoleDemo() { }

    /** Prints every event; synchronized so lines from different threads never mix. */
    private static class ConsoleListener implements MonitorListener {
        @Override public synchronized void onIncident(Incident i) { System.out.println("[ALERT   ] " + i); }
        @Override public synchronized void onFileProcessed(String file, String worker, int lines, int bad) {
            System.out.printf("[%-8s] Finished %-16s %d lines read, %d malformed%n", worker, file, lines, bad);
        }
        @Override public synchronized void onMalformedLine(String file, int n, String why) {
            System.out.printf("[SKIPPED ] %s line %d: %s%n", file, n, why);
        }
        @Override public synchronized void onFileError(String file, String msg) { System.out.println("[ERROR   ] " + file + ": " + msg); }
    }

    public static void run() throws Exception {
        System.out.println("=== Cybersecurity Incident and Log Monitoring System - concurrent demo ===");
        Path dataDir = Path.of("data-demo");
        SecurityMonitor monitor = new SecurityMonitor(dataDir, 20);
        monitor.addListener(new ConsoleListener());
        monitor.start();
        for (Path p : SampleLogGenerator.generate(Path.of("logs-demo"))) {
            monitor.submitLogFile(p);
        }
        monitor.awaitIdle(60_000);

        System.out.println();
        System.out.println(monitor.getManager().buildReport());
        System.out.printf("Log lines read: %d (malformed: %d), files: %d%n", monitor.getTotalLines(),
                monitor.getTotalMalformed(), monitor.getFilesDone());
        for (MonitorThread<?> t : monitor.getThreads()) {
            System.out.printf("  %-10s %-18s handled %d item(s)%n", t.getName(), t.getRole(), t.getProcessed());
        }

        // Incident record update and error handling
        System.out.println();
        List<Incident> medium = monitor.getManager().getIncidents(Severity.MEDIUM);
        String id = medium.get(0).getId();
        try {
            monitor.getManager().updateStatus(id, IncidentStatus.RESOLVED);
            System.out.println("[UPDATE  ] " + id + " moved to RESOLVED");
            monitor.getManager().updateStatus(id, IncidentStatus.OPEN);
        } catch (IncidentNotFoundException | InvalidStatusTransitionException e) {
            System.out.println("[REJECTED] " + e.getMessage());
        }
        try {
            monitor.getManager().updateStatus("INC-9999", IncidentStatus.RESOLVED);
        } catch (IncidentNotFoundException | InvalidStatusTransitionException e) {
            System.out.println("[REJECTED] " + e.getMessage());
        }
        monitor.shutdown();
        System.out.println("Data saved in folder: " + dataDir);
    }
}
