package com.logmonitor.service;

import com.logmonitor.exception.InvalidLogFormatException;
import com.logmonitor.model.AuthLogEntry;
import com.logmonitor.model.LogEntry;
import com.logmonitor.model.NetworkLogEntry;
import com.logmonitor.model.SystemLogEntry;

import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.regex.Pattern;

/**
 * Converts one text line of the form
 * "time | host | event | user | ip | detail" into a LogEntry object.
 */
public final class LogParser {
    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");

    private LogParser() { }

    public static LogEntry parse(String line) throws InvalidLogFormatException {
        String[] f = line.split("\\|", -1);
        if (f.length != 6) {
            throw new InvalidLogFormatException("Expected 6 fields but found " + f.length, line);
        }
        for (int i = 0; i < f.length; i++) {
            f[i] = f[i].trim();
        }
        LocalDateTime time;
        try {
            time = LocalDateTime.parse(f[0], LogEntry.FORMAT);
        } catch (DateTimeParseException e) {
            throw new InvalidLogFormatException("Invalid timestamp '" + f[0] + "'", line);
        }
        if (!validIp(f[4])) {
            throw new InvalidLogFormatException("Invalid IP address '" + f[4] + "'", line);
        }
        switch (f[2]) {
            case "LOGIN_SUCCESS": return new AuthLogEntry(time, f[1], f[3], f[4], true);
            case "LOGIN_FAILED":  return new AuthLogEntry(time, f[1], f[3], f[4], false);
            case "SYSTEM_COMMAND": return new SystemLogEntry(time, f[1], f[3], f[4], f[5]);
            case "PORT_CONNECT":
                try {
                    int port = Integer.parseInt(f[5]);
                    if (port < 1 || port > 65535) {
                        throw new InvalidLogFormatException("Port out of range: " + port, line);
                    }
                    return new NetworkLogEntry(time, f[1], f[3], f[4], port);
                } catch (NumberFormatException e) {
                    throw new InvalidLogFormatException("Invalid port number '" + f[5] + "'", line);
                }
            default:
                throw new InvalidLogFormatException("Unknown event type '" + f[2] + "'", line);
        }
    }

    private static boolean validIp(String ip) {
        var m = IPV4.matcher(ip);
        if (!m.matches()) return false;
        for (int i = 1; i <= 4; i++) {
            if (Integer.parseInt(m.group(i)) > 255) return false;
        }
        return true;
    }
}
