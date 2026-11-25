package com.logmonitor;

import com.logmonitor.service.SecurityMonitor;
import com.logmonitor.ui.MonitorFrame;

import javax.swing.SwingUtilities;

/** Entry point: no argument starts the Swing window, --demo runs the console demonstration. */
public final class Main {
    private Main() { }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("--demo")) {
            ConsoleDemo.run();
            return;
        }
        SecurityMonitor monitor = new SecurityMonitor(SecurityMonitor.defaultDataDir(), 25);
        SwingUtilities.invokeLater(() -> new MonitorFrame(monitor).setVisible(true));
    }
}
