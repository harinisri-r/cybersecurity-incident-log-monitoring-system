package com.logmonitor.ui;

import com.logmonitor.exception.IncidentNotFoundException;
import com.logmonitor.exception.InvalidStatusTransitionException;
import com.logmonitor.io.FileManager;
import com.logmonitor.io.SampleLogGenerator;
import com.logmonitor.model.Incident;
import com.logmonitor.model.IncidentStatus;
import com.logmonitor.model.LogEntry;
import com.logmonitor.service.IncidentManager;
import com.logmonitor.service.MonitorListener;
import com.logmonitor.service.MonitorThread;
import com.logmonitor.service.SecurityMonitor;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.FlowLayout;
import java.awt.event.ItemEvent;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/** The main screen: Dashboard, Incidents, Statistics and Alerts tabs. */
public class MonitorPanel extends JPanel implements MonitorListener {
    private static final Color NAVY = new Color(0x14, 0x2B, 0x4D);

    private final SecurityMonitor monitor;
    private final JTabbedPane tabs = new JTabbedPane();
    private final DefaultTableModel workerModel = readOnly("Thread", "Role", "Status", "Items handled");
    private final DefaultTableModel incidentModel = readOnly("ID", "Time", "Severity", "Category", "Source IP", "User", "Status", "Details");
    private final JTable incidentTable = new JTable(incidentModel);
    private final JComboBox<String> severityFilter = new JComboBox<>(new String[]{"All", "Critical", "High", "Medium", "Low"});
    private final JTextField searchField = new JTextField(14);
    private final JComboBox<IncidentStatus> statusCombo = new JComboBox<>(IncidentStatus.values());
    private final JTextArea activityLog = new JTextArea();
    private final JTextArea alertLog = new JTextArea();
    private final JTextArea statsArea = new JTextArea();
    private final JLabel[] cards = {new JLabel(), new JLabel(), new JLabel(), new JLabel(), new JLabel()};
    private final JLabel statusBar = new JLabel(" Ready");
    private javax.swing.Timer refreshTimer;

    public MonitorPanel(SecurityMonitor monitor) {
        super(new BorderLayout());
        this.monitor = monitor;
        add(buildBanner(), BorderLayout.NORTH);
        tabs.addTab("Dashboard", buildDashboard());
        tabs.addTab("Incidents", buildIncidentTab());
        tabs.addTab("Statistics", buildStatsTab());
        tabs.addTab("Alerts", buildAlertTab());
        add(tabs, BorderLayout.CENTER);
        statusBar.setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6));
        add(statusBar, BorderLayout.SOUTH);
        refreshAll();
    }

    private static DefaultTableModel readOnly(String... cols) {
        return new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
    }

    private JPanel buildBanner() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(NAVY);
        p.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        JLabel title = new JLabel("CYBERSECURITY INCIDENT AND LOG MONITORING SYSTEM");
        title.setForeground(Color.WHITE);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 16f));
        JLabel info = new JLabel(SecurityMonitor.FILE_WORKERS + " log workers + 1 incident responder | 6 detection rules");
        info.setForeground(new Color(0xFF, 0xC8, 0x57));
        p.add(title, BorderLayout.WEST);
        p.add(info, BorderLayout.EAST);
        return p;
    }

    // ---------------------------------------------------------------- Dashboard
    private JPanel buildDashboard() {
        JPanel root = new JPanel(new BorderLayout(0, 6));
        root.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        JButton loadSample = new JButton("Load Sample Logs");
        JButton addFile = new JButton("Add Log File...");
        JButton export = new JButton("Export Report");
        loadSample.addActionListener(e -> onLoadSample());
        addFile.addActionListener(e -> onAddFile());
        export.addActionListener(e -> onExport());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        buttons.add(loadSample);
        buttons.add(addFile);
        buttons.add(export);

        JPanel cardRow = new JPanel(new GridLayout(1, cards.length, 8, 0));
        for (JLabel c : cards) {
            c.setHorizontalAlignment(JLabel.CENTER);
            c.setOpaque(true);
            c.setBackground(new Color(0xEE, 0xF2, 0xF8));
            c.setBorder(BorderFactory.createLineBorder(new Color(0xB0, 0xBC, 0xD0)));
            cardRow.add(c);
        }
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.add(buttons);
        top.add(Box.createVerticalStrut(8));
        top.add(cardRow);
        root.add(top, BorderLayout.NORTH);

        JTable workers = new JTable(workerModel);
        workers.setRowHeight(22);
        JScrollPane workerScroll = new JScrollPane(workers);
        workerScroll.setBorder(BorderFactory.createTitledBorder("Monitoring threads (running concurrently)"));
        activityLog.setEditable(false);
        activityLog.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        JScrollPane activityScroll = new JScrollPane(activityLog);
        activityScroll.setBorder(BorderFactory.createTitledBorder("Activity log"));
        JPanel center = new JPanel(new GridLayout(2, 1, 0, 6));
        center.add(workerScroll);
        center.add(activityScroll);
        root.add(center, BorderLayout.CENTER);
        return root;
    }

    // ---------------------------------------------------------------- Incidents
    private JPanel buildIncidentTab() {
        JPanel root = new JPanel(new BorderLayout(0, 6));
        root.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        bar.add(new JLabel("Severity:"));
        bar.add(severityFilter);
        bar.add(new JLabel("Search:"));
        bar.add(searchField);
        bar.add(Box.createHorizontalStrut(20));
        bar.add(new JLabel("Set status:"));
        bar.add(statusCombo);
        JButton update = new JButton("Update Selected");
        bar.add(update);
        root.add(bar, BorderLayout.NORTH);

        // ItemListener: re-filter when another severity is chosen
        severityFilter.addItemListener(e -> {
            if (e.getStateChange() == ItemEvent.SELECTED) refreshIncidents();
        });
        // DocumentListener: re-filter while the analyst types
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { refreshIncidents(); }
            public void removeUpdate(DocumentEvent e) { refreshIncidents(); }
            public void changedUpdate(DocumentEvent e) { refreshIncidents(); }
        });
        // ActionListener: change the status of the selected incident record
        update.addActionListener(e -> onUpdateStatus());

        incidentTable.setRowHeight(22);
        incidentTable.setFont(incidentTable.getFont().deriveFont(11f));
        incidentTable.getColumnModel().getColumn(2).setCellRenderer(new SeverityRenderer());
        int[] widths = {62, 125, 62, 130, 98, 44, 105, 400};
        for (int i = 0; i < widths.length; i++) {
            incidentTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        root.add(new JScrollPane(incidentTable), BorderLayout.CENTER);
        return root;
    }

    /** TableCellRenderer: draws the severity as a coloured cell. */
    private static class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
            super.getTableCellRendererComponent(t, v, sel, focus, r, c);
            setHorizontalAlignment(CENTER);
            if (!sel) {
                switch (String.valueOf(v)) {
                    case "Critical" -> setBackground(new Color(0xE5, 0x39, 0x35));
                    case "High" -> setBackground(new Color(0xFF, 0x98, 0x3A));
                    case "Medium" -> setBackground(new Color(0xFF, 0xE0, 0x82));
                    default -> setBackground(new Color(0xA5, 0xD6, 0xA7));
                }
                setForeground(String.valueOf(v).equals("Critical") ? Color.WHITE : Color.BLACK);
            }
            return this;
        }
    }

    // ---------------------------------------------------------------- Statistics / Alerts
    private JPanel buildStatsTab() {
        statsArea.setEditable(false);
        statsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        p.add(new JScrollPane(statsArea), BorderLayout.CENTER);
        return p;
    }

    private JPanel buildAlertTab() {
        alertLog.setEditable(false);
        alertLog.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        p.add(new JScrollPane(alertLog), BorderLayout.CENTER);
        return p;
    }

    // ---------------------------------------------------------------- actions
    private void onLoadSample() {
        try {
            for (Path p : SampleLogGenerator.generate(Path.of("logs"))) monitor.submitLogFile(p);
            statusBar.setText(" 4 sample log files queued");
        } catch (IOException ex) {
            statusBar.setText(" Could not create sample logs: " + ex.getMessage());
        }
    }

    private void onAddFile() {
        JFileChooser chooser = new JFileChooser(".");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            monitor.submitLogFile(chooser.getSelectedFile().toPath());
            statusBar.setText(" Queued " + chooser.getSelectedFile().getName());
        }
    }

    private void onExport() {
        try {
            FileManager.writeReport(monitor.getManager().buildReport(), monitor.getReportFile());
            statusBar.setText(" Report saved to " + monitor.getReportFile());
        } catch (IOException ex) {
            statusBar.setText(" Could not save report: " + ex.getMessage());
        }
    }

    private void onUpdateStatus() {
        int row = incidentTable.getSelectedRow();
        if (row < 0) {
            statusBar.setText(" Select an incident first");
            return;
        }
        String id = String.valueOf(incidentModel.getValueAt(row, 0));
        try {
            monitor.getManager().updateStatus(id, (IncidentStatus) statusCombo.getSelectedItem());
            statusBar.setText(" " + id + " updated to " + statusCombo.getSelectedItem());
            refreshIncidents();
        } catch (IncidentNotFoundException | InvalidStatusTransitionException ex) {
            statusBar.setText(" " + ex.getMessage());
        }
    }

    // ---------------------------------------------------------------- refreshing
    public void startAutoRefresh() {
        refreshTimer = new javax.swing.Timer(500, e -> refreshAll());
        refreshTimer.start();
    }

    public void stopAutoRefresh() { if (refreshTimer != null) refreshTimer.stop(); }
    public void selectTab(int index) { tabs.setSelectedIndex(index); }
    public void setStatusText(String text) { statusBar.setText(" " + text); }

    public void refreshAll() {
        IncidentManager m = monitor.getManager();
        String[] titles = {"Files processed", "Log lines read", "Malformed lines", "Incidents", "Critical / High"};
        String[] values = {String.valueOf(monitor.getFilesDone()), String.valueOf(monitor.getTotalLines()),
                String.valueOf(monitor.getTotalMalformed()), String.valueOf(m.getTotal()),
                (m.getCount(com.logmonitor.model.Severity.CRITICAL)) + " / " + m.getCount(com.logmonitor.model.Severity.HIGH)};
        for (int i = 0; i < cards.length; i++) {
            cards[i].setText("<html><center><span style='font-size:9px;color:#555'>" + titles[i]
                    + "</span><br><b style='font-size:16px'>" + values[i] + "</b></center></html>");
        }
        workerModel.setRowCount(0);
        for (MonitorThread<?> t : monitor.getThreads()) {
            workerModel.addRow(new Object[]{t.getName(), t.getRole(), t.getStatus(), t.getProcessed()});
        }
        refreshIncidents();
        statsArea.setText(m.buildReport() + "\nMonitoring threads:\n" + threadSummary());
    }

    private String threadSummary() {
        StringBuilder sb = new StringBuilder();
        for (MonitorThread<?> t : monitor.getThreads()) {
            sb.append(String.format("  %-10s %-18s handled %d item(s)%n", t.getName(), t.getRole(), t.getProcessed()));
        }
        return sb.toString();
    }

    private void refreshIncidents() {
        String sev = String.valueOf(severityFilter.getSelectedItem());
        String text = searchField.getText().trim().toLowerCase();
        incidentModel.setRowCount(0);
        List<Incident> list = monitor.getManager().getIncidents();
        for (Incident i : list) {
            boolean sevOk = sev.equals("All") || i.getSeverity().getLabel().equals(sev);
            boolean textOk = text.isEmpty() || i.toString().toLowerCase().contains(text);
            if (sevOk && textOk) {
                incidentModel.addRow(new Object[]{i.getId(), i.getTime().format(LogEntry.FORMAT),
                        i.getSeverity().getLabel(), i.getCategory().getLabel(), i.getSourceIp(), i.getUser(),
                        i.getStatus(), i.getDescription()});
            }
        }
    }

    // ---------------------------------------------------------------- MonitorListener
    @Override
    public void onIncident(Incident i) {
        SwingUtilities.invokeLater(() -> {
            alertLog.append(i.toAlertLine() + "\n");
            activityLog.append("ALERT " + i.getSeverity().getLabel() + ": " + i.getCategory().getLabel() + " from " + i.getSourceIp() + "\n");
        });
    }

    @Override
    public void onFileProcessed(String file, String worker, int lines, int malformed) {
        SwingUtilities.invokeLater(() -> activityLog.append(worker + " finished " + file + ": " + lines
                + " lines, " + malformed + " malformed\n"));
    }

    @Override
    public void onMalformedLine(String file, int n, String reason) {
        SwingUtilities.invokeLater(() -> activityLog.append("SKIPPED " + file + " line " + n + ": " + reason + "\n"));
    }

    @Override
    public void onFileError(String file, String message) {
        SwingUtilities.invokeLater(() -> activityLog.append("ERROR " + file + ": " + message + "\n"));
    }
}
