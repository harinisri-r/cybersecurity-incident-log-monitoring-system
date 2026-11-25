package com.logmonitor.service;

import com.logmonitor.io.FileManager;
import com.logmonitor.model.Incident;
import com.logmonitor.rules.BruteForceRule;
import com.logmonitor.rules.CompromisedLoginRule;
import com.logmonitor.rules.DetectionRule;
import com.logmonitor.rules.OffHoursLoginRule;
import com.logmonitor.rules.PortScanRule;
import com.logmonitor.rules.PrivilegeEscalationRule;
import com.logmonitor.rules.SensitiveFileRule;

import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Facade of the system: owns the rules, the queues, the incident records and the monitoring threads. */
public class SecurityMonitor {
    public static final int FILE_WORKERS = 4;

    private final IncidentManager manager = new IncidentManager();
    private final List<DetectionRule> rules = List.of(new BruteForceRule(), new CompromisedLoginRule(),
            new OffHoursLoginRule(), new PrivilegeEscalationRule(), new SensitiveFileRule(), new PortScanRule());
    private final BlockingQueue<Path> fileQueue = new LinkedBlockingQueue<>();
    private final BlockingQueue<Incident> incidentQueue = new LinkedBlockingQueue<>();
    private final List<MonitorThread<?>> threads = new ArrayList<>();
    private final List<MonitorListener> listeners = new CopyOnWriteArrayList<>();
    private final AtomicInteger pendingFiles = new AtomicInteger();
    private final AtomicInteger pendingIncidents = new AtomicInteger();
    private final AtomicInteger totalLines = new AtomicInteger();
    private final AtomicInteger totalMalformed = new AtomicInteger();
    private final AtomicInteger filesDone = new AtomicInteger();
    private final Path dataDir;
    private final int delayMillis;
    private ExecutorService pool;

    public SecurityMonitor(Path dataDir, int delayMillisPerLine) {
        this.dataDir = dataDir;
        this.delayMillis = delayMillisPerLine;
        for (int i = 1; i <= FILE_WORKERS; i++) {
            threads.add(new LogFileWorker("Worker-" + i, this));
        }
        threads.add(new IncidentResponder("Responder", this));
    }

    /** Starts one thread per monitoring worker. */
    public void start() {
        pool = Executors.newFixedThreadPool(threads.size());
        for (MonitorThread<?> t : threads) pool.execute(t);
    }

    /** Called by the UI: queue a log file; a free worker will pick it up. */
    public void submitLogFile(Path file) {
        pendingFiles.incrementAndGet();
        fileQueue.offer(file);
    }

    void submitIncident(Incident incident) {
        pendingIncidents.incrementAndGet();
        incidentQueue.offer(incident);
    }

    public boolean awaitIdle(long timeoutMillis) throws InterruptedException {
        long end = System.currentTimeMillis() + timeoutMillis;
        while ((pendingFiles.get() > 0 || pendingIncidents.get() > 0) && System.currentTimeMillis() < end) {
            Thread.sleep(50);
        }
        return pendingFiles.get() == 0 && pendingIncidents.get() == 0;
    }

    /** Stops all threads and saves the incident records and the summary report. */
    public void shutdown() {
        for (MonitorThread<?> t : threads) t.stop();
        if (pool != null) {
            pool.shutdown();
            try {
                pool.awaitTermination(3, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        try {
            FileManager.saveIncidents(manager.getIncidents(), dataDir.resolve("incidents.csv"));
            FileManager.writeReport(manager.buildReport(), getReportFile());
        } catch (IOException e) {
            System.err.println("Could not save data: " + e.getMessage());
        }
    }

    // ---------- listener support (observer pattern) ----------
    public void addListener(MonitorListener l) { listeners.add(l); }
    void fireIncident(Incident i) { for (MonitorListener l : listeners) l.onIncident(i); }
    void fireMalformed(String f, int n, String why) { for (MonitorListener l : listeners) l.onMalformedLine(f, n, why); }
    void fireFileError(String f, String m) { for (MonitorListener l : listeners) l.onFileError(f, m); }
    void fireFileProcessed(String f, String w, int lines, int bad) {
        for (MonitorListener l : listeners) l.onFileProcessed(f, w, lines, bad);
    }

    // ---------- internal helpers used by the threads ----------
    void simulateWork() throws InterruptedException { if (delayMillis > 0) Thread.sleep(delayMillis); }
    void addCounts(int lines, int bad) { totalLines.addAndGet(lines); totalMalformed.addAndGet(bad); }
    void fileFinished() { filesDone.incrementAndGet(); pendingFiles.decrementAndGet(); }
    void incidentHandled() { pendingIncidents.decrementAndGet(); }
    BlockingQueue<Path> fileQueue() { return fileQueue; }
    BlockingQueue<Incident> incidentQueue() { return incidentQueue; }

    // ---------- accessors ----------
    public IncidentManager getManager() { return manager; }
    public List<DetectionRule> getRules() { return rules; }
    public List<MonitorThread<?>> getThreads() { return threads; }
    public int getTotalLines() { return totalLines.get(); }
    public int getTotalMalformed() { return totalMalformed.get(); }
    public int getFilesDone() { return filesDone.get(); }
    public int getPendingFiles() { return pendingFiles.get(); }
    public Path getDataDir() { return dataDir; }
    public Path getAlertFile() { return dataDir.resolve("alerts.log"); }
    public Path getReportFile() { return dataDir.resolve("security_report_" + LocalDate.now() + ".txt"); }
    public static Path defaultDataDir() { return Path.of("data"); }
}
