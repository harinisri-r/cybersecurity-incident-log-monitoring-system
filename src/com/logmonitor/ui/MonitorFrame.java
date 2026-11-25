package com.logmonitor.ui;

import com.logmonitor.service.SecurityMonitor;

import javax.swing.JFrame;
import java.awt.Dimension;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/** Main window. Closing it stops the monitoring threads and saves incidents and the report. */
public class MonitorFrame extends JFrame {
    public MonitorFrame(SecurityMonitor monitor) {
        super("Cybersecurity Incident and Log Monitoring System");
        MonitorPanel panel = new MonitorPanel(monitor);
        monitor.addListener(panel);
        monitor.start();
        panel.startAutoRefresh();
        setContentPane(panel);
        setPreferredSize(new Dimension(960, 600));
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                panel.stopAutoRefresh();
                monitor.shutdown();
                dispose();
                System.exit(0);
            }
        });
        pack();
        setLocationRelativeTo(null);
    }
}
