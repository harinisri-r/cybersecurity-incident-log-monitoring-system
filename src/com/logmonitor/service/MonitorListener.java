package com.logmonitor.service;

import com.logmonitor.model.Incident;

/** Observer interface: the monitor notifies every registered listener (GUI panel or text console). */
public interface MonitorListener {
    void onIncident(Incident incident);
    void onFileProcessed(String file, String worker, int lines, int malformed);
    void onMalformedLine(String file, int lineNumber, String reason);
    void onFileError(String file, String message);
}
