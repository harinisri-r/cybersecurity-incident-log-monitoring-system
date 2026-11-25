package com.logmonitor.io;

import com.logmonitor.model.Incident;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.stream.Stream;

/** All file input/output: log file list, alert log, incident records (CSV) and the summary report. */
public final class FileManager {
    private static final Object ALERT_LOCK = new Object();

    private FileManager() { }

    /** Appends one alert line to alerts.log. Locked because several threads may write. */
    public static void appendAlert(Incident incident, Path file) throws IOException {
        synchronized (ALERT_LOCK) {
            createParent(file);
            Files.writeString(file, incident.toAlertLine() + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        }
    }

    /** Saves all incident records as CSV. */
    public static void saveIncidents(List<Incident> incidents, Path file) throws IOException {
        createParent(file);
        try (BufferedWriter w = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
            w.write("id,time,severity,category,source_ip,user,host,status,description");
            w.newLine();
            for (Incident i : incidents) {
                w.write(i.toCsv());
                w.newLine();
            }
        }
    }

    public static void writeReport(String text, Path file) throws IOException {
        createParent(file);
        Files.writeString(file, text, StandardCharsets.UTF_8);
    }

    /** Lists the *.log files of a folder in alphabetical order. */
    public static List<Path> listLogFiles(Path dir) throws IOException {
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> p.getFileName().toString().endsWith(".log")).sorted().toList();
        }
    }

    private static void createParent(Path file) throws IOException {
        Path parent = file.getParent();
        if (parent != null) Files.createDirectories(parent);
    }
}
