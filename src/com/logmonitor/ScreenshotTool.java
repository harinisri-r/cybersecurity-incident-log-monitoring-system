package com.logmonitor;

import com.logmonitor.io.SampleLogGenerator;
import com.logmonitor.model.Incident;
import com.logmonitor.model.IncidentStatus;
import com.logmonitor.model.Severity;
import com.logmonitor.service.SecurityMonitor;
import com.logmonitor.ui.MonitorPanel;

import javax.imageio.ImageIO;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Path;

/** Renders the real GUI panel off-screen (headless) into PNG files used as report screenshots. */
public final class ScreenshotTool {
    private static final int W = 980, H = 560;

    public static void main(String[] args) throws Exception {
        System.setProperty("java.awt.headless", "true");
        Path out = Path.of(args[0]);
        Files.createDirectories(out);
        SecurityMonitor monitor = new SecurityMonitor(Path.of("data-shots"), 45);
        MonitorPanel[] holder = new MonitorPanel[1];
        SwingUtilities.invokeAndWait(() -> holder[0] = new MonitorPanel(monitor));
        MonitorPanel panel = holder[0];
        monitor.addListener(panel);
        monitor.start();
        for (Path p : SampleLogGenerator.generate(Path.of("logs-shots"))) monitor.submitLogFile(p);
        Thread.sleep(1100);
        shot(panel, 0, out.resolve("fig_dashboard_running.png"));
        monitor.awaitIdle(120_000);
        Thread.sleep(300);
        Incident low = monitor.getManager().getIncidents(Severity.MEDIUM).get(0);
        monitor.getManager().updateStatus(low.getId(), IncidentStatus.RESOLVED);
        panel.setStatusText(low.getId() + " updated to RESOLVED");
        shot(panel, 0, out.resolve("fig_dashboard_done.png"));
        shot(panel, 1, out.resolve("fig_incidents.png"));
        shot(panel, 2, out.resolve("fig_statistics.png"));
        shot(panel, 3, out.resolve("fig_alerts.png"));
        monitor.shutdown();
        System.exit(0);
    }

    private static void shot(MonitorPanel panel, int tab, Path file) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            panel.selectTab(tab);
            panel.refreshAll();
            panel.setSize(W, H);
            layoutAll(panel);
        });
        BufferedImage img = new BufferedImage(W, H, BufferedImage.TYPE_INT_RGB);
        SwingUtilities.invokeAndWait(() -> {
            Graphics2D g = img.createGraphics();
            panel.paint(g);
            g.dispose();
        });
        ImageIO.write(img, "png", file.toFile());
    }

    private static void layoutAll(Component c) {
        c.doLayout();
        if (c instanceof Container box) {
            for (Component child : box.getComponents()) layoutAll(child);
        }
    }
}
