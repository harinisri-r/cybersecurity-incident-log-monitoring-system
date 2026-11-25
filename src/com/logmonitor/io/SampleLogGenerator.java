package com.logmonitor.io;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/** Creates four realistic sample log files (one per server) so the system can be demonstrated. */
public final class SampleLogGenerator {
    private static final LocalDate DAY = LocalDate.of(2026, 11, 20);
    private static final String[] USERS = {"alice", "bob", "carol", "dave"};

    private SampleLogGenerator() { }

    public static List<Path> generate(Path dir) throws IOException {
        Files.createDirectories(dir);
        Random rnd = new Random(2026);
        List<Path> files = new ArrayList<>();
        files.add(write(dir.resolve("auth-server.log"), authServer(rnd), 9, "@@ corrupted entry - unreadable @@",
                27, "2026-13-45 99:99:99 | AUTH-SRV1 | LOGIN_FAILED | bob | 10.0.0.12 | Invalid password"));
        files.add(write(dir.resolve("web-server.log"), webServer(rnd), -1, null, -1, null));
        files.add(write(dir.resolve("vpn-gateway.log"), vpnGateway(), 12, "2026-11-20 10:15:00 | VPN-GW | PORT_CONNECT | alice | 10.0.0.11 | abc", -1, null));
        files.add(write(dir.resolve("db-server.log"), dbServer(), 4, "2026-11-20 10:10:10 | DB-SRV1 | SYSTEM_COMMAND | alice | 10.0.0.11", -1, null));
        return files;
    }

    private static String line(int h, int m, int s, String host, String type, String user, String ip, String detail) {
        return String.format("%s %02d:%02d:%02d | %s | %s | %s | %s | %s", DAY, h, m, s, host, type, user, ip, detail);
    }

    private static String internalIp(String user) {
        return "10.0.0." + (11 + java.util.Arrays.asList(USERS).indexOf(user));
    }

    private static List<String> authServer(Random rnd) {
        List<String> l = new ArrayList<>();
        for (int i = 0; i < 18; i++) {
            String u = USERS[rnd.nextInt(USERS.length)];
            l.add(line(8 + rnd.nextInt(9), rnd.nextInt(60), rnd.nextInt(60), "AUTH-SRV1", "LOGIN_SUCCESS", u, internalIp(u), "Password accepted"));
        }
        l.add(line(9, 30, 12, "AUTH-SRV1", "LOGIN_FAILED", "bob", "10.0.0.12", "Invalid password"));
        l.add(line(14, 2, 45, "AUTH-SRV1", "LOGIN_FAILED", "dave", "10.0.0.14", "Invalid password"));
        for (int i = 0; i < 12; i++) {
            l.add(line(13, 5, 10 + 3 * i, "AUTH-SRV1", "LOGIN_FAILED", "admin", "203.0.113.45", "Invalid password"));
        }
        l.add(line(13, 5, 58, "AUTH-SRV1", "LOGIN_SUCCESS", "admin", "203.0.113.45", "Password accepted"));
        return l;
    }

    private static List<String> webServer(Random rnd) {
        List<String> l = new ArrayList<>();
        for (int i = 0; i < 14; i++) {
            String u = USERS[rnd.nextInt(2)];
            l.add(line(8 + rnd.nextInt(9), rnd.nextInt(60), rnd.nextInt(60), "WEB-SRV1", "LOGIN_SUCCESS", u, internalIp(u), "Password accepted"));
        }
        l.add(line(11, 18, 20, "WEB-SRV1", "LOGIN_FAILED", "alice", "10.0.0.11", "Invalid password"));
        for (int i = 0; i < 6; i++) {
            l.add(line(16, 20, 5 + 5 * i, "WEB-SRV1", "LOGIN_FAILED", "root", "198.51.100.77", "Invalid password"));
        }
        l.add(line(2, 41, 9, "WEB-SRV1", "LOGIN_SUCCESS", "carol", "192.0.2.88", "Password accepted"));
        return l;
    }

    private static List<String> vpnGateway() {
        List<String> l = new ArrayList<>();
        l.add(line(8, 47, 31, "VPN-GW", "LOGIN_SUCCESS", "bob", "10.0.0.12", "Password accepted"));
        l.add(line(9, 12, 5, "VPN-GW", "LOGIN_SUCCESS", "alice", "10.0.0.11", "Password accepted"));
        l.add(line(3, 0, 2, "VPN-GW", "LOGIN_SUCCESS", "svc_backup", "10.0.0.50", "Password accepted"));
        l.add(line(23, 15, 44, "VPN-GW", "LOGIN_SUCCESS", "dave", "192.0.2.150", "Password accepted"));
        for (int i = 0; i < 6; i++) {
            l.add(line(10 + i, 5 * i, 11, "VPN-GW", "PORT_CONNECT", "-", "10.0.0." + (20 + i), "443"));
        }
        int[] ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5432, 8080};
        for (int i = 0; i < ports.length; i++) {
            l.add(line(19, 40, i, "VPN-GW", "PORT_CONNECT", "-", "203.0.113.99", String.valueOf(ports[i])));
        }
        return l;
    }

    private static List<String> dbServer() {
        List<String> l = new ArrayList<>();
        l.add(line(9, 0, 20, "DB-SRV1", "SYSTEM_COMMAND", "admin", "10.0.0.5", "sudo su"));
        l.add(line(9, 41, 3, "DB-SRV1", "SYSTEM_COMMAND", "admin", "10.0.0.5", "sudo systemctl restart mysql"));
        l.add(line(10, 5, 15, "DB-SRV1", "SYSTEM_COMMAND", "carol", "10.0.0.13", "tail -n 20 /var/log/mysql.log"));
        l.add(line(11, 32, 10, "DB-SRV1", "SYSTEM_COMMAND", "alice", "10.0.0.11", "sudo su"));
        l.add(line(11, 40, 51, "DB-SRV1", "SYSTEM_COMMAND", "alice", "10.0.0.11", "ls -l /var/db"));
        l.add(line(13, 15, 30, "DB-SRV1", "SYSTEM_COMMAND", "root", "10.0.0.5", "cat /etc/shadow"));
        l.add(line(15, 5, 44, "DB-SRV1", "SYSTEM_COMMAND", "bob", "10.0.0.12", "cat /etc/shadow"));
        l.add(line(16, 22, 8, "DB-SRV1", "SYSTEM_COMMAND", "carol", "10.0.0.13", "df -h"));
        l.add(line(21, 10, 3, "DB-SRV1", "SYSTEM_COMMAND", "dave", "10.0.0.14", "chmod 777 /var/db/backup"));
        return l;
    }

    /** Sorts the lines by time and inserts up to two corrupted lines at fixed positions. */
    private static Path write(Path file, List<String> lines, int pos1, String bad1, int pos2, String bad2) throws IOException {
        Collections.sort(lines);
        if (bad1 != null) lines.add(Math.min(pos1, lines.size()), bad1);
        if (bad2 != null) lines.add(Math.min(pos2, lines.size()), bad2);
        Files.write(file, lines, StandardCharsets.UTF_8);
        return file;
    }
}
