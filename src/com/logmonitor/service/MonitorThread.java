package com.logmonitor.service;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Abstract monitoring thread (template method): it repeatedly takes the next item from its queue
 * and calls process(), which each subclass implements in its own way.
 */
public abstract class MonitorThread<T> implements Runnable {
    private final String name;
    private final BlockingQueue<T> queue;
    private volatile boolean running = true;
    private volatile String status = "IDLE";
    private volatile int processed = 0;

    protected MonitorThread(String name, BlockingQueue<T> queue) {
        this.name = name;
        this.queue = queue;
    }

    /** Handles one queue item - different for a log-file worker and an incident responder. */
    protected abstract void process(T item);

    public abstract String getRole();

    @Override
    public void run() {
        while (running) {
            try {
                T item = queue.poll(200, TimeUnit.MILLISECONDS);
                if (item != null) {
                    process(item);
                    processed++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        status = "STOPPED";
    }

    public void stop() { running = false; }
    protected void setStatus(String status) { this.status = status; }
    public String getName() { return name; }
    public String getStatus() { return status; }
    public int getProcessed() { return processed; }
}
