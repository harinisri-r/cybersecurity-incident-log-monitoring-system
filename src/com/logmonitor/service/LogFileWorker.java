package com.logmonitor.service;

import com.logmonitor.exception.InvalidLogFormatException;
import com.logmonitor.model.LogEntry;
import com.logmonitor.rules.DetectionRule;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Monitoring thread that reads one log file line by line and applies every detection rule. */
public class LogFileWorker extends MonitorThread<Path> {
    private final SecurityMonitor monitor;

    public LogFileWorker(String name, SecurityMonitor monitor) {
        super(name, monitor.fileQueue());
        this.monitor = monitor;
    }

    @Override
    public String getRole() { return "Log file monitor"; }

    @Override
    protected void process(Path file) {
        String fileName = file.getFileName().toString();
        int lines = 0;
        int malformed = 0;
        setStatus("READING " + fileName);
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            int lineNo = 0;
            while ((line = reader.readLine()) != null) {
                lineNo++;
                if (line.isBlank() || line.startsWith("#")) continue;
                lines++;
                try {
                    LogEntry entry = LogParser.parse(line);
                    for (DetectionRule rule : monitor.getRules()) {
                        rule.evaluate(entry).ifPresent(monitor::submitIncident);
                    }
                } catch (InvalidLogFormatException e) {
                    malformed++;
                    monitor.fireMalformed(fileName, lineNo, e.getMessage());
                }
                monitor.simulateWork();
            }
            monitor.fireFileProcessed(fileName, getName(), lines, malformed);
        } catch (IOException e) {
            monitor.fireFileError(fileName, e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            setStatus("IDLE");
            monitor.addCounts(lines, malformed);
            monitor.fileFinished();
        }
    }
}
