package com.logmonitor.rules;

import java.time.LocalDateTime;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

/** Counts events per key (for example per IP address) inside a moving time window. */
final class SlidingWindow {
    private final Map<String, Deque<LocalDateTime>> events = new HashMap<>();

    /** Records an event and returns how many events of this key lie inside the window. */
    int add(String key, LocalDateTime time, long windowSeconds) {
        Deque<LocalDateTime> q = events.computeIfAbsent(key, k -> new ArrayDeque<>());
        q.addLast(time);
        return prune(q, time, windowSeconds);
    }

    /** Number of events of this key inside the window that ends at the given time. */
    int count(String key, LocalDateTime time, long windowSeconds) {
        Deque<LocalDateTime> q = events.get(key);
        return q == null ? 0 : prune(q, time, windowSeconds);
    }

    void clear(String key) { events.remove(key); }

    private static int prune(Deque<LocalDateTime> q, LocalDateTime now, long windowSeconds) {
        while (!q.isEmpty() && q.peekFirst().plusSeconds(windowSeconds).isBefore(now)) {
            q.removeFirst();
        }
        return q.size();
    }
}
